#
# Copyright (C) 2011-2013 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libstfl
PKG_VERSION:=0.22
PKG_RELEASE:=1

PKG_SOURCE:=stfl-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://www.clifford.at/stfl/
PKG_MDSUM:=df4998f69fed15fabd702a25777f74ab

PKG_INSTALL:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/stfl-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/libstfl
	SECTION:=lib
	CATEGORY:=Libraries
	DEPENDS:=+libncursesw +libpthread
	TITLE:=a curses-based widget set for text terminals
	URL:=http://www.clifford.at/stfl/
	MAINTAINER:=Entware team, wl500g-repo.googlecode.com
endef

define Package/libstfl/description
  STFL is a library which implements a curses-based widget set for text terminals
endef

TARGET_CPPFLAGS += \
	-I. \
	-fPIC \

TARGET_LDFLAGS += \
	-lncursesw \
	-lpthread \

MAKE_FLAGS += \
	CC="$(TARGET_CC) $(TARGET_CPPFLAGS)" \
	CFLAGS="$(TARGET_CFLAGS)"  \
	LDLIBS="$(TARGET_LDFLAGS)" \
	prefix=/opt \

define Build/InstallDev
	$(INSTALL_DIR) $(1)/opt/include/
	$(CP) $(PKG_INSTALL_DIR)/opt/include/*.h $(1)/opt/include/
	$(INSTALL_DIR) $(1)/opt/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/*.{a,so*} $(1)/opt/lib/
	$(INSTALL_DIR) $(1)/opt/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/pkgconfig/*.pc $(1)/opt/lib/pkgconfig/
endef

define Package/libstfl/install
	$(INSTALL_DIR) $(1)/opt/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/libstfl.so* $(1)/opt/lib
	$(LN) libstfl.so.$(PKG_VERSION) $(1)/opt/lib/libstfl.so.0
endef

$(eval $(call BuildPackage,libstfl))
