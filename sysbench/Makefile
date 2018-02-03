#
# Copyright (C) 2011-2017 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Пакет рабочий, для новых версий нужно собирать LuaJIT.
# Результаты странные, поэтому не добавил.
# Читаем https://github.com/akopytov/sysbench/issues/209

include $(TOPDIR)/rules.mk

PKG_NAME:=sysbench
PKG_VERSION:=0.5
PKG_RELEASE:=1
PKG_FIXUP:=autoreconf
#PKG_INSTALL:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/akopytov/sysbench
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=0.5

include $(INCLUDE_DIR)/package.mk

define Package/sysbench
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=a multi-threaded benchmark tool
	URL:=$(PKG_SOURCE_URL)
	MAINTAINER:=Entware team, http://entware.net
endef

define Package/sysbench/description
 sysbench is a multi-threaded benchmark tool based. It is most frequently used for database benchmarks,
 but can also be used to create arbitrarily complex workloads that do not involve a database server.
endef

CONFIGURE_ARGS += \
	--without-mysql


define Package/sysbench/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sysbench/sysbench $(1)/opt/bin
endef

$(eval $(call BuildPackage,sysbench))
