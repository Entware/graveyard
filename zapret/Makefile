#
# Copyright (C) 2018 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=zapret
PKG_VERSION:=0.19-20180818
PKG_REV:=48d778244cd3ddea1ff9a1532616ec2b7c4b2de7
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/bol-van/zapret.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk

define Package/zapret
	SECTION:=net
	CATEGORY:=Network
	DEPENDS:=+libnetfilter-queue
	TITLE:=DPI bypass tool
	URL:=$(PKG_SOURCE_URL)
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/zapret/description
 NFQUEUE based solution for ISP DPI bypass.
endef

define Build/Compile
	$(MAKE_VARS) \
	    $(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)/nfq $(MAKE_FLAGS)
	$(MAKE_VARS) \
	    $(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)/tpws $(MAKE_FLAGS)
endef

define Package/zapret/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nfq/nfqws $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tpws/tpws $(1)/opt/bin
endef

$(eval $(call BuildPackage,zapret))
