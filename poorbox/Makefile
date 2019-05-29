#
# Copyright (C) 2006-2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# 
# Этот вариант busysbox с минимумом апплетов для систем, где busybox вообще нет.
# 1. Можно понизить версию
# 2. Для изменения конфигурации следует выполнить make package/poorbox/configure
#    Зайти в папку poorbox, выполнить make menuconfig. Обновленный .config положить в files
#

include $(TOPDIR)/rules.mk

PKG_NAME:=poorbox
PKG_VERSION:=1.30.1
PKG_RELEASE:=1

PKG_SOURCE:=busybox-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=https://www.poorbox.net/downloads \
		http://sources.buildroot.net
PKG_HASH:=3d1d04a4dbd34048f4794815a5c48ebb9eb53c5277e09ffffc060323b95dfbdc

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_UNPACK=$(HOST_TAR) -C $(PKG_BUILD_DIR) --strip-components=1 -xf $(DL_DIR)/$(PKG_SOURCE)

PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define Package/poorbox
  SECTION:=base
  CATEGORY:=Base system
  TITLE:=Special version busybox
  URL:=http://busybox.net/
endef

define Package/poorbox/description
 The Swiss Army Knife of embedded Linux.
 It slices, it dices, it makes Julian Fries.
endef

LDLIBS:=m

MAKE_VARS :=
MAKE_FLAGS += \
	EXTRA_CFLAGS="$(TARGET_CFLAGS) $(TARGET_CPPFLAGS)" \
	EXTRA_LDFLAGS="$(TARGET_LDFLAGS)" \
	LDLIBS="$(LDLIBS)" \
	LD="$(TARGET_CC)" \
	SKIP_STRIP=y
ifneq ($(findstring c,$(OPENWRT_VERBOSE)),)
  MAKE_FLAGS += V=1
endif

define Build/Configure
	$(CP) ./files/.config $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(call Build/Compile/Default, \
		CONFIG_PREFIX="$(PKG_INSTALL_DIR)/opt" \
		all \
	)
endef

define Package/poorbox/install
	$(INSTALL_DIR) $(1)/opt/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/busybox $(1)/opt/usr/bin
	ln -sf busybox $(1)/opt/usr/bin/wget
	ln -sf busybox $(1)/opt/usr/bin/tar
	ln -sf busybox $(1)/opt/usr/bin/gunzip
	ln -sf busybox $(1)/opt/usr/bin/gzip
	ln -sf busybox $(1)/opt/usr/bin/tar
endef

$(eval $(call BuildPackage,poorbox))
