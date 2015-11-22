#
# Copyright (C) 2011-2012 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
#

include $(TOPDIR)/rules.mk

PKG_NAME:=pits
PKG_REV=12
PKG_VERSION:=1.0.0-r$(PKG_REV)
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://pits.googlecode.com/svn/trunk/
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_SOURCE_PROTO:=svn

include $(INCLUDE_DIR)/package.mk

define Package/pits
	SECTION:=net
	CATEGORY:=Network
	DEPENDS:=+libpolarssl
	TITLE:=a Google Cloudprint Proxy
	URL:=http://www.chromium.org/developers/design-documents/google-cloud-print-proxy-design
	MAINTAINER:=Entware team, wl500g-repo.googlecode.com
endef

define Package/pits/description
 A Google Cloudprint Proxy
endef

define Package/pits/conffiles
/opt/etc/pitsd.conf
endef

define Package/pits/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/pitsd $(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/etc
endef

$(eval $(call BuildPackage,pits))
