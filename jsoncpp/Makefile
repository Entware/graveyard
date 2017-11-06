#
# Copyright (C) 2011-2017 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Used by marc-fs only

include $(TOPDIR)/rules.mk

PKG_NAME:=jsoncpp
PKG_VERSION:=1.8.3
PKG_REV:=2de18021fcb11370e9b5a1fbe7dcfd673533a134
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/open-source-parsers/jsoncpp.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/jsoncpp
	SECTION:=libs
	CATEGORY:=Libraries
	DEPENDS:=+libstdcpp
	TITLE:=a C++ library for interacting with JSON.
	URL:=$(PKG_SOURCE_URL)
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/jsoncpp/description
 A C++ library for interacting with JSON.
endef

CMAKE_OPTIONS += \
	-DJSONCPP_WITH_TESTS=OFF \
	-DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF \
	-DBUILD_SHARED_LIBS=ON \
	-DBUILD_STATIC_LIBS=OFF

define Build/InstallDev
	$(INSTALL_DIR) $(1)/opt/include
	$(CP) $(PKG_INSTALL_DIR)/opt/include/json $(1)/opt/include
	$(CP) $(PKG_INSTALL_DIR)/opt/lib $(1)/opt
endef

define Package/jsoncpp/install
	$(INSTALL_DIR) $(1)/opt/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/libjsoncpp.so* $(1)/opt/lib
endef

$(eval $(call BuildPackage,jsoncpp))
