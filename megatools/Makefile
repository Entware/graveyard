#
# Copyright (C) 2011-2013 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Half of functions still not implemented, I have to return to this package later

include $(TOPDIR)/rules.mk

PKG_NAME:=megatools
PKG_VERSION:=1.9.92-20140906
PKG_REV:=e3b250f1c5b8725a2ea3373a9c871bf15d61686b
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=git://github.com/megous/megatools.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/megatools
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Filesystem
#DEPENDS:=+libneon +libfuse +libopenssl $(ICONV_DEPENDS) $(INTL_DEPENDS)
	TITLE:=command line client for Mega.co.nz
	URL:=http://megatools.megous.com/
	MAINTAINER:=Entware team, wl500g-repo.googlecode.com
endef

define Package/megatools/description
 command line client for Mega.co.nz
endef

CONFIGURE_ARGS += \
	--disable-docs-build \
	--disable-glibtest \
	--with-fuse \

define Package/megatools/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) \
	    $(PKG_BUILD_DIR)/tools/mega{reg,df,ls,fs} \
	    $(1)/opt/bin/
endef

$(eval $(call BuildPackage,megatools))
