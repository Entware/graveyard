#
# Copyright (C) 2020 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# It's working, but wants to keep all its dependancy statically linked
# So this package is just two binaries, 71MB total
# IMHO, it's too heavy to be packed.

include $(TOPDIR)/rules.mk

PKG_NAME:=mupdf
PKG_VERSION:=1.17.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-source.tar.xz
PKG_SOURCE_URL:=https://mupdf.com/downloads/archive
PKG_HASH:=16a2de72b899b35c02dfce5aae7d11cd40767116

PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)-source

include $(INCLUDE_DIR)/package.mk

define Package/mupdf
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+libopenssl
	TITLE:=DF, XPS, and E-book viewer
	URL:=https://mupdf.com
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/mupdf/description
 MuPDF is a lightweight PDF, XPS, and E-book viewer. This package contains
 software library and command line tools.
endef

MAKE_FLAGS += \
	HAVE_X11=no \
	HAVE_GLUT=no \
	USE_SYSTEM_LIBS=no \
	VERSION=$(PKG_VERSION) \
	verbose=yes

define Package/mupdf/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/release/mu{raster,tool} $(1)/opt/bin
endef

$(eval $(call BuildPackage,mupdf))
