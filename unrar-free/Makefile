#
# Copyright (C) 2011-2013 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
#

include $(TOPDIR)/rules.mk

PKG_NAME:=unrar-free
PKG_VERSION:=0.0.1-20071127
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=:pserver:anonymous@cvs.gna.org:/cvs/unrar
PKG_SOURCE_SUBDIR:=unrar
PKG_SOURCE_VERSION:=-D'11/27/2007'
PKG_SOURCE_PROTO:=cvs

PKG_BUILD_DEPENDS:=argp-standalone
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

PKG_UNPACK:=gzip -dc $(DL_DIR)/$(PKG_SOURCE) | $(TAR) -C $(PKG_BUILD_DIR) --strip-components=1 -xf -

define Package/unrar-free
	SECTION:=utils
	CATEGORY:=Utilities
	SUBMENU:=compression
	TITLE:=free unrar utility
	URL:=cvs.happy.kiev.ua
	MAINTAINER:=Entware team, wl500g-repo.googlecode.com
endef

define Package/unrar-free/description
 unrar is a free software version of the non-free unrar utility that exists on
 many GNU/Linux systems today.
endef

CONFIGURE_VARS += \
	LIBS=-largp

define Package/unrar-free/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/unrar $(1)/opt/bin/
endef

$(eval $(call BuildPackage,unrar-free))
