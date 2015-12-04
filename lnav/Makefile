#
# Copyright (C) 2011-2015 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Crashes with unknown reason

include $(TOPDIR)/rules.mk

PKG_NAME:=lnav
PKG_VERSION:=0.8.1-20151130
PKG_REV:=b6e10f4ee456a2d771a985d20da6f3d89e171871
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/tstack/lnav
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)

PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

define Package/lnav
	SECTION:=admin
	CATEGORY:=Administration
	DEPENDS:=+libpcrecpp +libreadline +libsqlite3 +libncursesw +libbz2 +zlib
	TITLE:=log navigator
	URL:=http://lnav.org
	MAINTAINER:=Entware team, entware.wl500g.info
endef

define Package/lnav/description
 An advanced log file viewer for the small-scale.
endef

CONFIGURE_ARGS += \
	--disable-static \
	--disable-tinfo \
	--without-libcurl \
	--without-jemalloc \
	--without-yajl \
	--with-pcre="$(STAGING_DIR)/opt" \
	--with-readline="$(STAGING_DIR)/opt" \
	--with-sqlite3="$(STAGING_DIR)/opt"

define Build/Compile
	touch $(PKG_BUILD_DIR)/src/{ptimec,bin2c}.o
	$(HOSTCXX) $(PKG_BUILD_DIR)/src/ptimec.cc -o $(PKG_BUILD_DIR)/src/ptimec
	$(HOSTCXX) $(PKG_BUILD_DIR)/src/bin2c.c -o $(PKG_BUILD_DIR)/src/bin2c
	$(call Build/Compile/Default)
endef

define Package/lnav/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/lnav $(1)/opt/bin
endef

$(eval $(call BuildPackage,lnav))
