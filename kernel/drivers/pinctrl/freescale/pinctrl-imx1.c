// SPDX-License-Identifier: GPL-2.0+
//
// i.MX1 pinctrl driver based on imx pinmux core
//
// Copyright (C) 2014 Alexander Shiyan <shc_work@mail.ru>

#include <linux/init.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pinctrl/pinctrl.h>

#include "pinctrl-imx1.h"

#define PAD_ID(port, pin)	((port) * 32 + (pin))
#define PA	0
#define PB	1
#define PC	2
#define PD	3

enum imx1_pads {
	MX1_PAD_A24		= PAD_ID(PA, 0),
	MX1_PAD_TIN		= PAD_ID(PA, 1),
	MX1_PAD_PWMO		= PAD_ID(PA, 2),
	MX1_PAD_CSI_MCLK	= PAD_ID(PA, 3),
	MX1_PAD_CSI_D0		= PAD_ID(PA, 4),
	MX1_PAD_CSI_D1		= PAD_ID(PA, 5),
	MX1_PAD_CSI_D2		= PAD_ID(PA, 6),
	MX1_PAD_CSI_D3		= PAD_ID(PA, 7),
	MX1_PAD_CSI_D4		= PAD_ID(PA, 8),
	MX1_PAD_CSI_D5		= PAD_ID(PA, 9),
	MX1_PAD_CSI_D6		= PAD_ID(PA, 10),
	MX1_PAD_CSI_D7		= PAD_ID(PA, 11),
	MX1_PAD_CSI_VSYNC	= PAD_ID(PA, 12),
	MX1_PAD_CSI_HSYNC	= PAD_ID(PA, 13),
	MX1_PAD_CSI_PIXCLK	= PAD_ID(PA, 14),
	MX1_PAD_I2C_SDA		= PAD_ID(PA, 15),
	MX1_PAD_I2C_SCL		= PAD_ID(PA, 16),
	MX1_PAD_DTACK		= PAD_ID(PA, 17),
	MX1_PAD_BCLK		= PAD_ID(PA, 18),
	MX1_PAD_LBA		= PAD_ID(PA, 19),
	MX1_PAD_ECB		= PAD_ID(PA, 20),
	MX1_PAD_A0		= PAD_ID(PA, 21),
	MX1_PAD_CS4		= PAD_ID(PA, 22),
	MX1_PAD_CS5		= PAD_ID(PA, 23),
	MX1_PAD_A16		= PAD_ID(PA, 24),
	MX1_PAD_A17		= PAD_ID(PA, 25),
	MX1_PAD_A18		= PAD_ID(PA, 26),
	MX1_PAD_A19		= PAD_ID(PA, 27),
	MX1_PAD_A20		= PAD_ID(PA, 28),
	MX1_PAD_A21		= PAD_ID(PA, 29),
	MX1_PAD_A22		= PAD_ID(PA, 30),
	MX1_PAD_A23		= PAD_ID(PA, 31),
	MX1_PAD_SD_DAT0		= PAD_ID(PB, 8),
	MX1_PAD_SD_DAT1		= PAD_ID(PB, 9),
	MX1_PAD_SD_DAT2		= PAD_ID(PB, 10),
	MX1_PAD_SD_DAT3		= PAD_ID(PB, 11),
	MX1_PAD_SD_SCLK		= PAD_ID(PB, 12),
	MX1_PAD_SD_CMD		= PAD_ID(PB, 13),
	MX1_PAD_SIM_SVEN	= PAD_ID(PB, 14),
	MX1_PAD_SIM_PD		= PAD_ID(PB, 15),
	MX1_PAD_SIM_TX		= PAD_ID(PB, 16),
	MX1_PAD_SIM_RX		= PAD_ID(PB, 17),
	MX1_PAD_SIM_RST		= PAD_ID(PB, 18),
	MX1_PAD_SIM_CLK		= PAD_ID(PB, 19),
	MX1_PAD_USBD_AFE	= PAD_ID(PB, 20),
	MX1_PAD_USBD_OE		= PAD_ID(PB, 21),
	MX1_PAD_USBD_RCV	= PAD_ID(PB, 22),
	MX1_PAD_USBD_SUSPND	= PAD_ID(PB, 23),
	MX1_PAD_USBD_VP		= PAD_ID(PB, 24),
	MX1_PAD_USBD_VM		= PAD_ID(PB, 25),
	MX1_PAD_USBD_VPO	= PAD_ID(PB, 26),
	MX1_PAD_USBD_VMO	= PAD_ID(PB, 27),
	MX1_PAD_UART2_CTS	= PAD_ID(PB, 28),
	MX1_PAD_UART2_RTS	= PAD_ID(PB, 29),
	MX1_PAD_UART2_TXD	= PAD_ID(PB, 30),
	MX1_PAD_UART2_RXD	= PAD_ID(PB, 31),
	MX1_PAD_SSI_RXFS	= PAD_ID(PC, 3),
	MX1_PAD_SSI_RXCLK	= PAD_ID(PC, 4),
	MX1_PAD_SSI_RXDAT	= PAD_ID(PC, 5),
	MX1_PAD_SSI_TXDAT	= PAD_ID(PC, 6),
	MX1_PAD_SSI_TXFS	= PAD_ID(PC, 7),
	MX1_PAD_SSI_TXCLK	= PAD_ID(PC, 8),
	MX1_PAD_UART1_CTS	= PAD_ID(PC, 9),
	MX1_PAD_UART1_RTS	= PAD_ID(PC, 10),
	MX1_PAD_UART1_TXD	= PAD_ID(PC, 11),
	MX1_PAD_UART1_RXD	= PAD_ID(PC, 12),
	MX1_PAD_SPI1_RDY	= PAD_ID(PC, 13),
	MX1_PAD_SPI1_SCLK	= PAD_ID(PC, 14),
	MX1_PAD_SPI1_SS		= PAD_ID(PC, 15),
	MX1_PAD_SPI1_MISO	= PAD_ID(PC, 16),
	MX1_PAD_SPI1_MOSI	= PAD_ID(PC, 17),
	MX1_PAD_BT13		= PAD_ID(PC, 19),
	MX1_PAD_BT12		= PAD_ID(PC, 20),
	MX1_PAD_BT11		= PAD_ID(PC, 21),
	MX1_PAD_BT10		= PAD_ID(PC, 22),
	MX1_PAD_BT9		= PAD_ID(PC, 23),
	MX1_PAD_BT8		= PAD_ID(PC, 24),
	MX1_PAD_BT7		= PAD_ID(PC, 25),
	MX1_PAD_BT6		= PAD_ID(PC, 26),
	MX1_PAD_BT5		= PAD_ID(PC, 27),
	MX1_PAD_BT4		= PAD_ID(PC, 28),
	MX1_PAD_BT3		= PAD_ID(PC, 29),
	MX1_PAD_BT2		= PAD_ID(PC, 30),
	MX1_PAD_BT1		= PAD_ID(PC, 31),
	MX1_PAD_LSCLK		= PAD_ID(PD, 6),
	MX1_PAD_REV		= PAD_ID(PD, 7),
	MX1_PAD_CLS		= PAD_ID(PD, 8),
	MX1_PAD_PS		= PAD_ID(PD, 9),
	MX1_PAD_SPL_SPR		= PAD_ID(PD, 10),
	MX1_PAD_CONTRAST	= PAD_ID(PD, 11),
	MX1_PAD_ACD_OE		= PAD_ID(PD, 12),
	MX1_PAD_LP_HSYNC	= PAD_ID(PD, 13),
	MX1_PAD_FLM_VSYNC	= PAD_ID(PD, 14),
	MX1_PAD_LD0		= PAD_ID(PD, 15),
	MX1_PAD_LD1		= PAD_ID(PD, 16),
	MX1_PAD_LD2		= PAD_ID(PD, 17),
	MX1_PAD_LD3		= PAD_ID(PD, 18),
	MX1_PAD_LD4		= PAD_ID(PD, 19),
	MX1_PAD_LD5		= PAD_ID(PD, 20),
	MX1_PAD_LD6		= PAD_ID(PD, 21),
	MX1_PAD_LD7		= PAD_ID(PD, 22),
	MX1_PAD_LD8		= PAD_ID(PD, 23),
	MX1_PAD_LD9		= PAD_ID(PD, 24),
	MX1_PAD_LD10		= PAD_ID(PD, 25),
	MX1_PAD_LD11		= PAD_ID(PD, 26),
	MX1_PAD_LD12		= PAD_ID(PD, 27),
	MX1_PAD_LD13		= PAD_ID(PD, 28),
	MX1_PAD_LD14		= PAD_ID(PD, 29),
	MX1_PAD_LD15		= PAD_ID(PD, 30),
	MX1_PAD_TMR2OUT		= PAD_ID(PD, 31),
};

/* Pad names for the pinmux subsystem */
static const struct pinctrl_pin_desc imx1_pinctrl_pads[] = {
	IMX_PINCTRL_PIN(MX1_PAD_A24),
	IMX_PINCTRL_PIN(MX1_PAD_TIN),
	IMX_PINCTRL_PIN(MX1_PAD_PWMO),
	IMX_PINCTRL_PIN(MX1_PAD_CSI_MCLK),
	IMX_PINCTRL_PIN(MX1_PAD_CSI_D0),
	IMX_PINCTRL_PIN(MX1_PAD_CSI_D1),
	IMX_PINCTRL_PIN(MX1_PAD_CSI_D2),
	IMX_PINCTRL_PIN(MX1_PAD_CSI_D3),
	IMX_PINCTRL_PIN(MX1_PAD_CSI_D4),
	IMX_PINCTRL_PIN(MX1_PAD_CSI_D5),
	IMX_PINCTRL_PIN(MX1_PAD_CSI_D6),
	IMX_PINCTRL_PIN(MX1_PAD_CSI_D7),
	IMX_PINCTRL_PIN(MX1_PAD_CSI_VSYNC),
	IMX_PINCTRL_PIN(MX1_PAD_CSI_HSYNC),
	IMX_PINCTRL_PIN(MX1_PAD_CSI_PIXCLK),
	IMX_PINCTRL_PIN(MX1_PAD_I2C_SDA),
	IMX_PINCTRL_PIN(MX1_PAD_I2C_SCL),
	IMX_PINCTRL_PIN(MX1_PAD_DTACK),
	IMX_PINCTRL_PIN(MX1_PAD_BCLK),
	IMX_PINCTRL_PIN(MX1_PAD_LBA),
	IMX_PINCTRL_PIN(MX1_PAD_ECB),
	IMX_PINCTRL_PIN(MX1_PAD_A0),
	IMX_PINCTRL_PIN(MX1_PAD_CS4),
	IMX_PINCTRL_PIN(MX1_PAD_CS5),
	IMX_PINCTRL_PIN(MX1_PAD_A16),
	IMX_PINCTRL_PIN(MX1_PAD_A17),
	IMX_PINCTRL_PIN(MX1_PAD_A18),
	IMX_PINCTRL_PIN(MX1_PAD_A19),
	IMX_PINCTRL_PIN(MX1_PAD_A20),
	IMX_PINCTRL_PIN(MX1_PAD_A21),
	IMX_PINCTRL_PIN(MX1_PAD_A22),
	IMX_PINCTRL_PIN(MX1_PAD_A23),
	IMX_PINCTRL_PIN(MX1_PAD_SD_DAT0),
	IMX_PINCTRL_PIN(MX1_PAD_SD_DAT1),
	IMX_PINCTRL_PIN(MX1_PAD_SD_DAT2),
	IMX_PINCTRL_PIN(MX1_PAD_SD_DAT3),
	IMX_PINCTRL_PIN(MX1_PAD_SD_SCLK),
	IMX_PINCTRL_PIN(MX1_PAD_SD_CMD),
	IMX_PINCTRL_PIN(MX1_PAD_SIM_SVEN),
	IMX_PINCTRL_PIN(MX1_PAD_SIM_PD),
	IMX_PINCTRL_PIN(MX1_PAD_SIM_TX),
	IMX_PINCTRL_PIN(MX1_PAD_SIM_RX),
	IMX_PINCTRL_PIN(MX1_PAD_SIM_CLK),
	IMX_PINCTRL_PIN(MX1_PAD_USBD_AFE),
	IMX_PINCTRL_PIN(MX1_PAD_USBD_OE),
	IMX_PINCTRL_PIN(MX1_PAD_USBD_RCV),
	IMX_PINCTRL_PIN(MX1_PAD_USBD_SUSPND),
	IMX_PINCTRL_PIN(MX1_PAD_USBD_VP),
	IMX_PINCTRL_PIN(MX1_PAD_USBD_VM),
	IMX_PINCTRL_PIN(MX1_PAD_USBD_VPO),
	IMX_PINCTRL_PIN(MX1_PAD_USBD_VMO),
	IMX_PINCTRL_PIN(MX1_PAD_UART2_CTS),
	IMX_PINCTRL_PIN(MX1_PAD_UART2_RTS),
	IMX_PINCTRL_PIN(MX1_PAD_UART2_TXD),
	IMX_PINCTRL_PIN(MX1_PAD_UART2_RXD),
	IMX_PINCTRL_PIN(MX1_PAD_SSI_RXFS),
	IMX_PINCTRL_PIN(MX1_PAD_SSI_RXCLK),
	IMX_PINCTRL_PIN(MX1_PAD_SSI_RXDAT),
	IMX_PINCTRL_PIN(MX1_PAD_SSI_TXDAT),
	IMX_PINCTRL_PIN(MX1_PAD_SSI_TXFS),
	IMX_PINCTRL_PIN(MX1_PAD_SSI_TXCLK),
	IMX_PINCTRL_PIN(MX1_PAD_UART1_CTS),
	IMX_PINCTRL_PIN(MX1_PAD_UART1_RTS),
	IMX_PINCTRL_PIN(MX1_PAD_UART1_TXD),
	IMX_PINCTRL_PIN(MX1_PAD_UART1_RXD),
	IMX_PINCTRL_PIN(MX1_PAD_SPI1_RDY),
	IMX_PINCTRL_PIN(MX1_PAD_SPI1_SCLK),
	IMX_PINCTRL_PIN(MX1_PAD_SPI1_SS),
	IMX_PINCTRL_PIN(MX1_PAD_SPI1_MISO),
	IMX_PINCTRL_PIN(MX1_PAD_SPI1_MOSI),
	IMX_PINCTRL_PIN(MX1_PAD_BT13),
	IMX_PINCTRL_PIN(MX1_PAD_BT12),
	IMX_PINCTRL_PIN(MX1_PAD_BT11),
	IMX_PINCTRL_PIN(MX1_PAD_BT10),
	IMX_PINCTRL_PIN(MX1_PAD_BT9),
	IMX_PINCTRL_PIN(MX1_PAD_BT8),
	IMX_PINCTRL_PIN(MX1_PAD_BT7),
	IMX_PINCTRL_PIN(MX1_PAD_BT6),
	IMX_PINCTRL_PIN(MX1_PAD_BT5),
	IMX_PINCTRL_PIN(MX1_PAD_BT4),
	IMX_PINCTRL_PIN(MX1_PAD_BT3),
	IMX_PINCTRL_PIN(MX1_PAD_BT2),
	IMX_PINCTRL_PIN(MX1_PAD_BT1),
	IMX_PINCTRL_PIN(MX1_PAD_LSCLK),
	IMX_PINCTRL_PIN(MX1_PAD_REV),
	IMX_PINCTRL_PIN(MX1_PAD_CLS),
	IMX_PINCTRL_PIN(MX1_PAD_PS),
	IMX_PINCTRL_PIN(MX1_PAD_SPL_SPR),
	IMX_PINCTRL_PIN(MX1_PAD_CONTRAST),
	IMX_PINCTRL_PIN(MX1_PAD_ACD_OE),
	IMX_PINCTRL_PIN(MX1_PAD_LP_HSYNC),
	IMX_PINCTRL_PIN(MX1_PAD_FLM_VSYNC),
	IMX_PINCTRL_PIN(MX1_PAD_LD0),
	IMX_PINCTRL_PIN(MX1_PAD_LD1),
	IMX_PINCTRL_PIN(MX1_PAD_LD2),
	IMX_PINCTRL_PIN(MX1_PAD_LD3),
	IMX_PINCTRL_PIN(MX1_PAD_LD4),
	IMX_PINCTRL_PIN(MX1_PAD_LD5),
	IMX_PINCTRL_PIN(MX1_PAD_LD6),
	IMX_PINCTRL_PIN(MX1_PAD_LD7),
	IMX_PINCTRL_PIN(MX1_PAD_LD8),
	IMX_PINCTRL_PIN(MX1_PAD_LD9),
	IMX_PINCTRL_PIN(MX1_PAD_LD10),
	IMX_PINCTRL_PIN(MX1_PAD_LD11),
	IMX_PINCTRL_PIN(MX1_PAD_LD12),
	IMX_PINCTRL_PIN(MX1_PAD_LD13),
	IMX_PINCTRL_PIN(MX1_PAD_LD14),
	IMX_PINCTRL_PIN(MX1_PAD_LD15),
	IMX_PINCTRL_PIN(MX1_PAD_TMR2OUT),
};

static struct imx1_pinctrl_soc_info imx1_pinctrl_info = {
	.pins	= imx1_pinctrl_pads,
	.npins	= ARRAY_SIZE(imx1_pinctrl_pads),
};

static int __init imx1_pinctrl_probe(struct platform_device *pdev)
{
	return imx1_pinctrl_core_probe(pdev, &imx1_pinctrl_info);
}

static const struct of_device_id imx1_pinctrl_of_match[] = {
	{ .compatible = "fsl,imx1-iomuxc", },
	{ }
};

static struct platform_driver imx1_pinctrl_driver = {
	.driver	= {
		.name		= "imx1-pinctrl",
		.of_match_table	= imx1_pinctrl_of_match,
		.suppress_bind_attrs = true,
	},
};
builtin_platform_driver_probe(imx1_pinctrl_driver, imx1_pinctrl_probe);
