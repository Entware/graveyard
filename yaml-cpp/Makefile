#
# Copyright (C) 2011-2015 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Used by asciiportal only

include $(TOPDIR)/rules.mk

PKG_NAME:=yaml-cpp
PKG_VERSION:=0.2.6
PKG_REV:=d98687afc372836aee4bdccb8475fa50814b8a8f
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/jbeder/yaml-cpp.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/yaml-cpp
	SECTION:=libs
	CATEGORY:=Libraries
	TITLE:=A YAML parser and emitter in C++
	URL:=https://github.com/jbeder/yaml-cpp
	MAINTAINER:=Entware team, entware.wl500g.info
endef

define Package/yaml-cpp/description
 yaml-cpp is a YAML parser and emitter in C++ matching the YAML 1.2 spec.
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/opt/include $(1)/opt/lib $(1)/opt/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/opt/include/yaml-cpp $(1)/opt/include/
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/libyaml-cpp.a $(1)/opt/lib/
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/pkgconfig/yaml-cpp.pc $(1)/opt/lib/pkgconfig/
endef

$(eval $(call BuildPackage,yaml-cpp))
