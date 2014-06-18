/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * PHY and RF functions
 *
 * Copyright (c) 2000-2005 ZyDAS Technology Corporation
 * Copyright (c) 2007-2009 Atheros Communications, Inc.
 * Copyright	2009	Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2009-2011	Christian Lamparter <chunkeey@googlemail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "carl9170.h"
#include "timer.h"
#include "printf.h"
#include "rf.h"
#include "shared/phy.h"

#ifdef CONFIG_CARL9170FW_RADIO_FUNCTIONS
static void set_channel_end(void)
{
	/* Manipulate CCA threshold to resume transmission */
	set(AR9170_PHY_REG_CCA_THRESHOLD, 0x0);
	/* Disable Virtual CCA */
	andl(AR9170_MAC_REG_QOS_PRIORITY_VIRTUAL_CCA,
	     ~AR9170_MAC_VIRTUAL_CCA_ALL);

	fw.phy.state = CARL9170_PHY_ON;
}

void rf_notify_set_channel(void)
{
	/* Manipulate CCA threshold to stop transmission */
	set(AR9170_PHY_REG_CCA_THRESHOLD, 0x300);
	/* Enable Virtual CCA */
	orl(AR9170_MAC_REG_QOS_PRIORITY_VIRTUAL_CCA,
	    AR9170_MAC_VIRTUAL_CCA_ALL);

	/* reset CCA stats */
	fw.tally.active = 0;
	fw.tally.cca = 0;
	fw.tally.tx_time = 0;
	fw.phy.state = CARL9170_PHY_OFF;
}

/*
 * Update delta slope coeff man and exp
 */
static void hw_turn_off_dyn(const uint32_t delta_slope_coeff_exp,
			    const uint32_t delta_slope_coeff_man,
			    const uint32_t delta_slope_coeff_exp_shgi,
			    const uint32_t delta_slope_coeff_man_shgi)
{
	uint32_t tmp;

	tmp = get_async(AR9170_PHY_REG_TIMING3) & 0x00001fff;
	tmp |= (delta_slope_coeff_man << AR9170_PHY_TIMING3_DSC_MAN_S) &
		AR9170_PHY_TIMING3_DSC_MAN;
	tmp |= (delta_slope_coeff_exp << AR9170_PHY_TIMING3_DSC_EXP_S) &
		AR9170_PHY_TIMING3_DSC_EXP;

	set(AR9170_PHY_REG_TIMING3, tmp);

	tmp = (delta_slope_coeff_man_shgi << AR9170_PHY_HALFGI_DSC_MAN_S) &
		AR9170_PHY_HALFGI_DSC_MAN;

	tmp |= (delta_slope_coeff_exp_shgi << AR9170_PHY_HALFGI_DSC_EXP_S) &
		AR9170_PHY_HALFGI_DSC_EXP;

	set(AR9170_PHY_REG_HALFGI, tmp);
}

static void program_ADDAC(void)
{
	/* ??? Select Internal ADDAC ??? (is external radio) */
	set(AR9170_PHY_REG_ADC_SERIAL_CTL, AR9170_PHY_ADC_SCTL_SEL_EXTERNAL_RADIO);

	delay(10);

	set(0x1c589c, 0x00000000);	/*# 7-0 */
	set(0x1c589c, 0x00000000);	/*# 15-8 */
	set(0x1c589c, 0x00000000);	/*# 23-16 */
	set(0x1c589c, 0x00000000);	/*# 31- */

	set(0x1c589c, 0x00000000);	/*# 39- */
	set(0x1c589c, 0x00000000);	/*# 47- */
	set(0x1c589c, 0x00000000);	/*# 55- [48]:doubles the xtalosc bias current */
	set(0x1c589c, 0x00000000);	/*# 63- */

	set(0x1c589c, 0x00000000);	/*# 71- */
	set(0x1c589c, 0x00000000);	/*# 79- */
	set(0x1c589c, 0x00000000);	/*# 87- */
	set(0x1c589c, 0x00000000);	/*# 95- */

	set(0x1c589c, 0x00000000);	/*# 103- */
	set(0x1c589c, 0x00000000);	/*# 111- */
	set(0x1c589c, 0x00000000);	/*# 119- */
	set(0x1c589c, 0x00000000);	/*# 127- */

	set(0x1c589c, 0x00000000);	/*# 135- */
	set(0x1c589c, 0x00000000);	/*# 143- */
	set(0x1c589c, 0x00000000);	/*# 151- */
	set(0x1c589c, 0x00000030);	/*# 159- #[158:156]=xlnabufmode */

	set(0x1c589c, 0x00000004);	/*# 167-  [162]:disable clkp_driver to flow */
	set(0x1c589c, 0x00000000);	/*# 175- */
	set(0x1c589c, 0x00000000);	/*# 183-176 */
	set(0x1c589c, 0x00000000);	/*# 191-184 */

	set(0x1c589c, 0x00000000);	/*# 199- */
	set(0x1c589c, 0x00000000);	/*# 207- */
	set(0x1c589c, 0x00000000);	/*# 215- */
	set(0x1c589c, 0x00000000);	/*# 223- */

	set(0x1c589c, 0x00000000);	/*# 231- */
	set(0x1c58c4, 0x00000000);	/*# 233-232 */

	delay(10);

	/* Select External Flow ???? (is internal addac??) */
	set(AR9170_PHY_REG_ADC_SERIAL_CTL, AR9170_PHY_ADC_SCTL_SEL_INTERNAL_ADDAC);
}

static uint32_t AGC_calibration(uint32_t loop)
{
	uint32_t wrdata;
	uint32_t ret;

#define AGC_CAL_NF	(AR9170_PHY_AGC_CONTROL_CAL | AR9170_PHY_AGC_CONTROL_NF)

	wrdata = get_async(AR9170_PHY_REG_AGC_CONTROL) | AGC_CAL_NF;
	set(AR9170_PHY_REG_AGC_CONTROL, wrdata);

	ret = get_async(AR9170_PHY_REG_AGC_CONTROL) & AGC_CAL_NF;

	/* sitesurvey : 100 ms / current connected 200 ms */
	while ((ret != 0) && loop--) {
		udelay(100);

		ret = get_async(AR9170_PHY_REG_AGC_CONTROL) & AGC_CAL_NF;
	}

	/* return the AGC/Noise calibration state to the driver */
	return ret;
}

#define EIGHTY_FLAG (CARL9170FW_PHY_HT_ENABLE | CARL9170FW_PHY_HT_DYN2040)

static uint32_t rf_init(const uint32_t delta_slope_coeff_exp,
			const uint32_t delta_slope_coeff_man,
			const uint32_t delta_slope_coeff_exp_shgi,
			const uint32_t delta_slope_coeff_man_shgi,
			const uint32_t finiteLoopCount,
			const bool initialize)
{
	uint32_t ret;

	hw_turn_off_dyn(delta_slope_coeff_exp,
			delta_slope_coeff_man,
			delta_slope_coeff_exp_shgi,
			delta_slope_coeff_man_shgi);

	if (initialize) {
		/* Real Chip */
		program_ADDAC();

		/* inverse chain 0 <-> chain 2 */
		set(AR9170_PHY_REG_ANALOG_SWAP, AR9170_PHY_ANALOG_SWAP_AB);

		/* swap chain 0 and chain 2 */
		set(AR9170_PHY_REG_ANALOG_SWAP, AR9170_PHY_ANALOG_SWAP_AB |
						AR9170_PHY_ANALOG_SWAP_ALT_CHAIN);

		/* Activate BB */
		set(AR9170_PHY_REG_ACTIVE, AR9170_PHY_ACTIVE_EN);
		delay(10);
	}

	ret = AGC_calibration(finiteLoopCount);

	set_channel_end();
	return ret;
}

void rf_cmd(const struct carl9170_cmd *cmd, struct carl9170_rsp *resp)
{
	uint32_t ret;

	fw.phy.ht_settings = cmd->rf_init.ht_settings;
	fw.phy.frequency = cmd->rf_init.freq;

	/*
	 * Is the clock controlled by the PHY?
	 */
	if ((fw.phy.ht_settings & EIGHTY_FLAG) == EIGHTY_FLAG)
		clock_set(AHB_80_88MHZ, true);
	else
		clock_set(AHB_40_44MHZ, true);

	ret = rf_init(le32_to_cpu(cmd->rf_init.delta_slope_coeff_exp),
		      le32_to_cpu(cmd->rf_init.delta_slope_coeff_man),
		      le32_to_cpu(cmd->rf_init.delta_slope_coeff_exp_shgi),
		      le32_to_cpu(cmd->rf_init.delta_slope_coeff_man_shgi),
		      le32_to_cpu(cmd->rf_init.finiteLoopCount),
		      cmd->hdr.cmd == CARL9170_CMD_RF_INIT);

	resp->hdr.len = sizeof(struct carl9170_rf_init_result);
	resp->rf_init_res.ret = cpu_to_le32(ret);
}

void rf_psm(void)
{
	u32 bank3;

	if (fw.phy.psm.state == CARL9170_PSM_SOFTWARE) {
		/* not enabled by the driver */
		return;
	}

	if (fw.phy.psm.state & CARL9170_PSM_SLEEP) {
		fw.phy.psm.state &= ~CARL9170_PSM_SLEEP;

		/* disable all agc gain and offset updates to a2 */
		set(AR9170_PHY_REG_TEST2, 0x8000000);

		/* power down ADDAC */
		set(AR9170_PHY_REG_ADC_CTL,
		    AR9170_PHY_ADC_CTL_OFF_PWDDAC |
		    AR9170_PHY_ADC_CTL_OFF_PWDADC |
		    0xa0000000);

		/* Synthesizer off + RX off */
		bank3 = 0x00400018;

		fw.phy.state = CARL9170_PHY_OFF;
	} else {
		/* advance to the next PSM step */
		fw.phy.psm.state--;

		if (fw.phy.psm.state == CARL9170_PSM_WAKE) {
			/* wake up ADDAC */
			set(AR9170_PHY_REG_ADC_CTL,
			    AR9170_PHY_ADC_CTL_OFF_PWDDAC |
			    AR9170_PHY_ADC_CTL_OFF_PWDADC);

			/* enable all agc gain and offset updates to a2 */
			set(AR9170_PHY_REG_TEST2, 0x0);

			/* Synthesizer on + RX on */
			bank3 = 0x01420098;

			fw.phy.state = CARL9170_PHY_ON;
		} else {
			return ;
		}
	}

	if (fw.phy.frequency < 3000000)
		bank3 |= 0x00800000;

	set(0x1c58f0, bank3);
}

#endif /* CONFIG_CARL9170FW_RADIO_FUNCTIONS */
