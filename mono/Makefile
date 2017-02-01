#
# Copyright (C) 2011-2017 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=mono
PKG_VERSION:=4.2.0.179
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=http://download.mono-project.com/sources/mono
PKG_MDSUM:=ebef5c86a3caa7f63b698f61b93b4318

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-4.2.0

include $(INCLUDE_DIR)/package.mk

define Package/mono
	SECTION:=utils
	CATEGORY:=Utilities
#	DEPENDS:=+libpthread +libstdcpp
	TITLE:=.NET framework
	URL:=http://www.mono-project.com
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/mono/description
 Cross platform, open source .NET framework
endef

CONFIGURE_ARGS += \
	--disable-libraries \
	--disable-mcs-build \
	--disable-mcs-build \
	--enable-minimal=aot,profiler,debug \
	--with-ikvm-native=no \
	--with-mcs-docs=no \
	--with-crosspkgdir=$(STAGING_DIR)/opt/lib/pkg-config \
	--with-static_mono=yes

CONFIGURE_VARS += \
	ac_cv_header_fstab_h=no

define Package/mono/install
	$(INSTALL_DIR) $(1)/opt
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/{mono,bximage} \
		$(1)/opt/bin
endef

$(eval $(call BuildPackage,mono))
