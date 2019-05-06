#
# Copyright (C) 2019 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# This is the last version without macro_predef host compilation
# It's working package, just without few shebang fixes in perl scripts needed

include $(TOPDIR)/rules.mk

PKG_NAME:=exim
PKG_VERSION:=4.89
PKG_RELEASE:=1

PKG_SOURCE_URL:=ftp://mirror.easyname.at/exim-ftp/exim/exim4/old
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.xz
PKG_HASH:=0c490a1ca97bbb22d6079d2896de19af48ac3af109ea5f307dbc6b49c66e9626

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/exim
	SECTION:=mail
	CATEGORY:=Mail
	TITLE:=MTA
	URL:=https://www.exim.org/
	DEPENDS:=+libdb47 +libpcre
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/exim/description
 Exim is a message transfer agent (MTA) developed at the University of
 Cambridge. In style it is similar to Smail 3, but its facilities are more
 general. There is a great deal of flexibility in the way mail can be routed,
 and there are extensive facilities for checking incoming mail.
endef

define Build/Configure
	$(CP) $(PKG_BUILD_DIR)/src/EDITME $(PKG_BUILD_DIR)/Local/Makefile
	$(call Build/Configure/Default)
endef

MAKE_FLAGS += \
	LFLAGS="$(TARGET_LDFLAGS)" \
	AR="$(TARGET_AR) cq"

MAKE_VARS += \
	INSTALL_ARG="-no_chown"

define Build/Install
	$(INSTALL_DIR) $(PKG_INSTALL_DIR)/etc
	$(call Build/Install/Default)
endef

define Package/exim/conffiles
/opt/etc/exim/configure
/opt/etc/exim/aliases
endef

define Package/exim/install
	$(INSTALL_DIR) $(1)/opt/etc/exim
	$(CP) $(PKG_INSTALL_DIR)/opt/exim/bin $(1)/opt
	$(INSTALL_CONF) $(PKG_INSTALL_DIR)/opt/exim/configure $(1)/opt/etc/exim
	$(INSTALL_CONF) $(PKG_INSTALL_DIR)/etc/aliases $(1)/opt/etc/exim
endef

$(eval $(call BuildPackage,exim))
