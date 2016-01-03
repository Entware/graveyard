#
# Copyright (C) 2011-2016 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=glog
PKG_VERSION:=0.3.3
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://google-glog.googlecode.com/files
PKG_MD5SUM:=a6fd2c22f8996846e34c763422717c18

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/glog
	SECTION:=libs
	CATEGORY:=Libraries
	DEPENDS:=+libstdcpp +libpthread
	TITLE:=application-level logging library
	URL:=http://code.google.com/p/google-glog/
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/glog/description
 The glog library implements application-level logging. This library provides
 logging APIs based on C++-style streams and various helper macros.
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/opt/include/glog
	$(CP) $(PKG_INSTALL_DIR)/opt/include/glog/*.h $(1)/opt/include/glog
	$(INSTALL_DIR) $(1)/opt/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/libglog.{a,la,so*} $(1)/opt/lib/
	$(INSTALL_DIR) $(1)/opt/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/pkgconfig/libglog.pc $(1)/opt/lib/pkgconfig/
endef

define Package/glog/install
	$(INSTALL_DIR) $(1)/opt/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/libglog.so* $(1)/opt/lib
endef

$(eval $(call BuildPackage,glog))
