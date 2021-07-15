#
# Copyright (C) 2021 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# It's working. Not sure it's worth to be a part of repo.
# libpcre2 support taken from https://github.com/ggreer/the_silver_searcher/pull/1035


include $(TOPDIR)/rules.mk

PKG_NAME:=silversearcher-ag
PKG_VERSION:=2.2.0
PKG_RELEASE:=1

PKG_SOURCE:=the_silver_searcher-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://geoff.greer.fm/ag/releases
PKG_HASH:=d9621a878542f3733b5c6e71c849b9d1a830ed77cb1a1f6c2ea441d4b0643170

PKG_FIXUP:=autoreconf

PKG_BUILD_DIR:=$(BUILD_DIR)/the_silver_searcher-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/silversearcher-ag
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+libpcre2 +liblzma +zlib
	TITLE:=a tool for searching code
	URL:=https://geoff.greer.fm/ag/
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/silversearcher-ag/description
 The Silver Searcher is a tool for searching code. It started off as a clone of
 Ack, but their feature sets have since diverged slightly.
endef

CONFIGURE_ARGS += \
	--with-pcre2

TARGET_LDFLAGS += -lpcre2-8

define Package/silversearcher-ag/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ag $(1)/opt/bin
endef

$(eval $(call BuildPackage,silversearcher-ag))
