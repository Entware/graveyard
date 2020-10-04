#
# Copyright (C) 2020 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Working package, just a joke

include $(TOPDIR)/rules.mk

PKG_NAME:=cmatrix
PKG_VERSION:=2.0
PKG_RELEASE:=1

PKG_SOURCE:=v$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/abishekvashok/cmatrix/archive
PKG_HASH:=ad93ba39acd383696ab6a9ebbed1259ecf2d3cf9f49d6b97038c66f80749e99a

PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

define Package/cmatrix
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+libncurses
	TITLE:=Console based \"The Matrix\" like implementation
	URL:=https://github.com/abishekvashok/cmatrix
	MAINTAINER:=Keeper <hd_keeper@mail.ru>
endef

CONFIGURE_ARGS +=  --without-fonts

define Package/cmatrix/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cmatrix $(1)/opt/bin/
endef

$(eval $(call BuildPackage,cmatrix))
