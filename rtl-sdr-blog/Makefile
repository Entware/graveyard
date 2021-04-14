#
# Copyright (C) 2011-2021 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Won't add, too many forks already added

include $(TOPDIR)/rules.mk

PKG_NAME:=rtl-sdr-blog
PKG_VERSION:=1.0.1-20210329
PKG_REV:=031a044e31e80a2258a7305eb7015708a8277104
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/rtlsdrblog/rtl-sdr-blog.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_MIRROR_HASH:=skip

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/rtl-sdr-blog
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+libusb-1.0
	TITLE:=enhacements RTL-SDR Blog V3 units
	URL:=$(PKG_SOURCE_URL)
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/rtl-sdr-blog/description
 Modified Osmocom drivers with enhancements for RTL-SDR Blog V3 units.
endef

TARGET_CFLAGS += $(FPIC)

define Package/rtl-sdr-blog/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(CP) $(PKG_INSTALL_DIR)/opt/bin/rtl_* $(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/librtlsdr.so* $(1)/opt/lib

endef

$(eval $(call BuildPackage,rtl-sdr-blog))
