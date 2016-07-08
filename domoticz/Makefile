# https://github.com/Entware-ng/Entware-ng/issues/333#issuecomment-231226044
# no usb devices are detected

#
# Copyright (C) 2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_REV:=4834
PKG_NAME:=domoticz
PKG_VERSION:=3.${PKG_REV}
PKG_RELEASE:=1
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/domoticz/domoticz.git
PKG_SOURCE_VERSION:=83981251af7660e4b0608d8b8502cf6642f4f7bd
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)

CMAKE_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/domoticz
  SECTION:=domoticz
  CATEGORY:=Domoticz
  TITLE:=Domoticz Home Automation 
  DEPENDS:=+zlib +libusb-1.0 +libusb-compat +libcurl +libsqlite3 +libopenssl +boost +boost-system +boost-thread +boost-date_time
  URL:=https://domoticz.com/
  MAINTAINER:=balintkozma <balint.kozma@gmail.com>
endef

define Package/domoticz/description
  Domoticz is a Home Automation System that lets you monitor and configure various devices like: 
  Lights, Switches, various sensors/meters like Temperature, Rain, Wind, UV, Electra, Gas, Water and much more. 
  Notifications/Alerts can be sent to any mobile device.
endef


CMAKE_FIND_ROOT_PATH := $(subst /usr,,$(CMAKE_FIND_ROOT_PATH))
TARGET_CFLAGS := $(filter-out -Wl\,-z\,now -Wl\,-z\,relro,$(TARGET_CFLAGS))
TARGET_LDFLAGS := $(filter-out -znow -zrelro,$(TARGET_LDFLAGS))
        
CMAKE_OPTIONS += \
	-DCMAKE_BUILD_TYPE=Release . \
	-DCPACK_STRIP_FILES=1
#       -DDEBUG=1

TARGET_CFLAGS += -I$(STAGING_DIR)/opt/include


define Package/domoticz/install
	$(INSTALL_DIR) $(1)/opt/share/domoticz $(1)/opt/bin
	$(CP) $(PKG_INSTALL_DIR)/opt/domoticz $(1)/opt/share/domoticz/
	$(CP) $(PKG_INSTALL_DIR)/opt/www $(1)/opt/share/domoticz/
	$(CP) $(PKG_INSTALL_DIR)/opt/Config $(1)/opt/share/domoticz/
	$(CP) $(PKG_INSTALL_DIR)/opt/scripts $(1)/opt/share/domoticz/
	ln -sf /opt/share/domoticz/domoticz $(1)/opt/bin/domoticz
endef

$(eval $(call BuildPackage,domoticz))
