#
# Copyright (C) 2011-2014 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=finch
PKG_VERSION:=2.10.10
PKG_RELEASE:=1

PKG_SOURCE:=pidgin-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=@SF/pidgin/Pidgin/$(PKG_VARSION)
PKG_MD5SUM:=5030d4750c73b211c7e82bb67ea3d016

PKG_INSTALL:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/pidgin-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/finch
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Instant Messaging
	DEPENDS:=+libncursesw +glib2 +libsasl2 +libxml2 +libgnutls +libidn
	TITLE:=a console-based modular messaging client
	URL:=http://pidgin.im
	MAINTAINER:=Entware team, entware.wl500g.info
endef

define Package/finch/description
 Finch is a console-based modular messaging client based on libpurple which is
 capable of connecting to AIM, MSN, Yahoo!, XMPP, ICQ, IRC, SILC, Novell
 GroupWise, Lotus Sametime, Zephyr, Gadu-Gadu, and QQ all at once. It has many
 common features found in other clients, as well as many unique features.
endef

CONFIGURE_ARGS += \
	--disable-gtkui \
	--enable-consoleui \
	--disable-screensaver \
	--disable-sm \
	--disable-gtkspell \
	--disable-gestures \
	--disable-schemas-install \
	--disable-gstreamer \
	--disable-farstream \
	--disable-vv \
	--disable-meanwhile \
	--disable-avahi \
	--disable-fortify \
	--disable-dbus \
	--disable-perl \
	--disable-tcl \
	--enable-cyrus-sasl \
	--disable-doxygen \
	--disable-devhelp \
	--without-x \
	--without-python \
	--with-ncurses-headers=$(STAGING_DIR)/opt/include/ncursesw \

TARGET_LDFLAGS += \
	-Wl,-rpath,/opt/lib/purple-2

define Package/finch/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/finch $(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/lib/{finch,gnt,purple-2}
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/lib*.so* $(1)/opt/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/finch/gnt*.so $(1)/opt/lib/finch
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/gnt/*.so $(1)/opt/lib/gnt
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/purple-2/*.so* $(1)/opt/lib/purple-2
	$(INSTALL_DIR) $(1)/opt/share/purple/ca-certs
	$(CP) $(PKG_INSTALL_DIR)/opt/share/purple/ca-certs/*.pem \
	    $(1)/opt/share/purple/ca-certs
endef

$(eval $(call BuildPackage,finch))
