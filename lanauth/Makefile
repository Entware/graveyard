#
# Copyright (C) 2011-2017 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=lanauth
PKG_VERSION:=r42
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/lanauth
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+libopenssl
	TITLE:=lanauth a command line auth tool for Kabinet (www.telenet.ru) provider
	URL:=http://kabauth.web-drive.org/bin/source/
	MAINTAINER:=Entware team, http://entware.net
endef

#define Package/lanauth/description
#endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(INSTALL_DATA) ./src/lanauth.c $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -I$(STAGING_DIR)/opt/include \
	    $(TARGET_LDFLAGS) -L$(STAGING_DIR)/opt/lib \
	    -o $(PKG_BUILD_DIR)/lanauth $(PKG_BUILD_DIR)/lanauth.c
endef

define Package/lanauth/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lanauth $(1)/opt/bin
endef

$(eval $(call BuildPackage,lanauth))
