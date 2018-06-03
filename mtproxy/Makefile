#
# Copyright (C) 2018 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
#common/crc32c.c:617:17: warning: 'crc32c_combine_clmul' defined but not used [-Wunused-function]
# static unsigned crc32c_combine_clmul (unsigned crc1, unsigned crc2, int64_t len2) {
#                 ^~~~~~~~~~~~~~~~~~~~
#{standard input}: Assembler messages:
#{standard input}:45: Error: unrecognized opcode `crc32b ($4),$6'

include $(TOPDIR)/rules.mk

PKG_NAME:=mtproxy
PKG_VERSION:=20180603
PKG_REV:=cdd348294d86e74442bb29bd6767e48321259bec
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_REV).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/TelegramMessenger/MTProxy.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk

define Package/mtproxy
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Web Servers/Proxies
#	DEPENDS:=+libpthread
	TITLE:=mtproxy for Telegram messenger
	URL:=$(PKG_SOURCE_URL)
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/mtproxy/description
 MTProxy is a Telegram messenger proxy.
endef

MAKE_VARS += \
	COMMIT="$(PKG_REV)"

define Package/mtproxy/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mtproto-proxy $(1)/opt/bin
endef

$(eval $(call BuildPackage,mtproxy))
