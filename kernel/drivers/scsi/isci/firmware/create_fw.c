#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <asm/types.h>
#include <strings.h>
#include <stdint.h>

#include "create_fw.h"

int write_blob(struct isci_orom *isci_orom)
{
	FILE *fd;
	int err;
	size_t count;

	fd = fopen(blob_name, "w+");
	if (!fd) {
		perror("Open file for write failed");
		fclose(fd);
		return -EIO;
	}

	count = fwrite(isci_orom, sizeof(struct isci_orom), 1, fd);
	if (count != 1) {
		perror("Write data failed");
		fclose(fd);
		return -EIO;
	}

	fclose(fd);

	return 0;
}

void set_binary_values(struct isci_orom *isci_orom)
{
	int c, phy_idx, port_idx;

	/* setting OROM signature */
	strncpy(isci_orom->hdr.signature, sig, strlen(sig));
	isci_orom->hdr.version = version;
	isci_orom->hdr.total_block_length = sizeof(struct isci_orom);
	isci_orom->hdr.hdr_length = sizeof(struct sci_bios_oem_param_block_hdr);
	isci_orom->hdr.num_elements = num_elements;

	for (c = 0; c < 2; c++) {
		struct sci_oem_params *ctrl = &isci_orom->ctrl[c];
		__u8 cable_selection_mask = 0;

		ctrl->controller.mode_type = mode_type;
		ctrl->controller.max_concurr_spin_up = max_num_concurrent_dev_spin_up;
		ctrl->controller.do_enable_ssc = enable_ssc;

		for (port_idx = 0; port_idx < SCI_MAX_PORTS; port_idx++)
			ctrl->ports[port_idx].phy_mask = phy_mask[c][port_idx];

		for (phy_idx = 0; phy_idx < SCI_MAX_PHYS; phy_idx++) {
			struct sci_phy_oem_params *phy = &ctrl->phys[phy_idx];
			__u8 cable_phy = cable_selection[c][phy_idx];

			phy->sas_address.high = sas_addr[c][phy_idx] >> 32;
			phy->sas_address.low = sas_addr[c][phy_idx];

			phy->afe_tx_amp_control0 = afe_tx_amp_control0;
			phy->afe_tx_amp_control1 = afe_tx_amp_control1;
			phy->afe_tx_amp_control2 = afe_tx_amp_control2;
			phy->afe_tx_amp_control3 = afe_tx_amp_control3;

			cable_selection_mask |= (cable_phy & 1) << phy_idx;
			cable_selection_mask |= (cable_phy & 2) << (phy_idx + 3);
		}
		ctrl->controller.cable_selection_mask = cable_selection_mask;
	}
}

int main(void)
{
	int err;
	struct isci_orom *isci_orom;

	isci_orom = malloc(sizeof(struct isci_orom));
	memset(isci_orom, 0, sizeof(struct isci_orom));

	set_binary_values(isci_orom);

	err = write_blob(isci_orom);
	if (err < 0) {
		free(isci_orom);
		return err;
	}

	free(isci_orom);
	return 0;
}
