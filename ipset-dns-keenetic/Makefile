#
# Copyright (C) 2023 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

PKG_NAME:=ipset-dns-keenetic
PKG_VERSION:=0.2
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/ipset-dns-keenetic
	SECTION:=net
	CATEGORY:=Network
	DEPENDS:=+ipset +ipset-dns +iptables
	TITLE:=selective routing on Keenetic
	PKGARCH:=all
endef

define Build/Compile
endef

define Package/ipset-dns-keenetic/conffiles
/opt/etc/bypass.conf
endef

define Package/ipset-dns-keenetic/install
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/S52ipset-dns $(1)/opt/etc/init.d
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/bypass.conf $(1)/opt/etc
	$(INSTALL_DIR) $(1)/opt/etc/ndm/netfilter.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/010-bypass-netfilter.sh $(1)/opt/etc/ndm/netfilter.d
	$(INSTALL_DIR) $(1)/opt/etc/ndm/ifstatechanged.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/010-bypass-table.sh $(1)/opt/etc/ndm/ifstatechanged.d
endef

$(eval $(call BuildPackage,ipset-dns-keenetic))
