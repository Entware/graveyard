#
# Copyright (C) 2011-2021 Entware
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

# Something wrong with syscalls on kernel 4.9 MIPS target
#vfs_map_name_to_handle_at :FSAL :DEBUG :Error Function not implemented (89) bytes = 48
#vfs_lookup_path :FSAL :CRIT :Could not get handle for path /xxx, error Function not implemented
#posix2fsal_error :FSAL :CRIT :Default case mapping Function not implemented (89) to ERR_FSAL_SERVERFAULT

include $(TOPDIR)/rules.mk

PKG_NAME:=nfs-ganesha
PKG_VERSION:=3.5
PKG_REV:=ff0401165d7fcdccb494431effc007be657ac68c
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=https://github.com/nfs-ganesha/nfs-ganesha.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_MIRROR_HASH:=3e94e18b5bb018fdbc12759e0853b6b9c383b00e0920b942772551e38773892e

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

CMAKE_SOURCE_SUBDIR:=src

CMAKE_OPTIONS += \
	-DUSE_FSAL_LUSTRE=OFF \
	-DUSE_FSAL_CEPH=OFF \
	-DUSE_DBUS=OFF \
	-DUSE_9P=OFF \
	-DPROXY_HANDLE_MAPPING=ON \
	-DUSE_GUI_ADMIN_TOOLS=OFF

define Package/nfs-ganesha
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Filesystem
	DEPENDS:=+krb5-libs +libcap +liburcu +libatomic +libblkid +libsqlite3
	TITLE:=NFS user mode Fileserver
	URL:=$(PKG_SOURCE_URL)
	MAINTAINER:=Entware team, https://entware.net
endef

define Package/nfs-ganesha/description
 NFS-Ganesha is an NFSv3,v4,v4.1 fileserver that runs in user mode on most
 UNIX/Linux systems.
endef

define Package/nfs-ganesha/conffiles
/opt/etc/ganesha/ganesha.conf
/opt/etc/ganesha/netconfig
endef

define Package/nfs-ganesha/postinst
#!/bin/sh

[ -e /opt/etc/netconfig ] || ln -s /opt/etc/ganesha/netconfig /opt/etc/netconfig
endef

define Package/nfs-ganesha/install
	$(INSTALL_DIR) $(1)/opt/bin $(1)/opt/var/lib/nfs
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/opt/bin/ganesha.nfsd $(1)/opt/bin
	$(INSTALL_DIR) $(1)/opt/lib
	$(CP) $(PKG_INSTALL_DIR)/opt/lib/{lib*,ganesha} $(1)/opt/lib
	$(INSTALL_DIR) $(1)/opt/etc/ganesha
	$(INSTALL_CONF) $(PKG_INSTALL_DIR)/opt/etc/ganesha/ganesha.conf \
		$(1)/opt/etc/ganesha
	$(INSTALL_CONF) files/netconfig $(1)/opt/etc/ganesha
endef

$(eval $(call BuildPackage,nfs-ganesha))
