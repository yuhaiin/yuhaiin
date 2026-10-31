// Package privatefs creates temporary backup material with private access.
package privatefs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
	"uuid"

	"golang.org/x/sys/windows"
)

// Windows ignores Unix mode bits when creating a file. Supply a protected
// DACL at creation, before any plaintext or secret can be written.
func securityAttributes(directory bool) (*windows.SecurityAttributes, *windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, nil, err
	}
	flags := ""
	if directory {
		flags = "OICI"
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;%s;FA;;;%s)(A;%s;FA;;;SY)", flags, user.User.Sid, flags))
	if err != nil {
		return nil, nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}, user.User.Sid, nil
}

// Check the actual object and volume, not just the path used to create it.
// A filesystem that does not enforce ACLs must not receive plaintext staging
// or the external backup identity.
func verifyPrivate(handle windows.Handle, user *windows.SID, directory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return errors.New("backup staging object is not the expected regular file or directory")
	}
	var flags uint32
	if err := windows.GetVolumeInformationByHandle(handle, nil, 0, nil, nil, &flags, nil, 0); err != nil {
		return err
	}
	if flags&windows.FILE_PERSISTENT_ACLS == 0 {
		return errors.New("backup staging filesystem does not enforce persistent ACLs")
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("backup staging ACL is not protected from inheritance")
	}
	acl, _, err := descriptor.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return errors.New("backup staging ACL is missing")
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return err
	}
	var hasUser bool
	for i := range uint32(acl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("backup staging ACL has an unexpected entry")
		}
		if directory && (ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE || ace.Header.AceFlags&(windows.INHERIT_ONLY_ACE|windows.NO_PROPAGATE_INHERIT_ACE) != 0) {
			return errors.New("backup staging ACL cannot protect descendants")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(user) && !sid.Equals(system) {
			return errors.New("backup staging ACL grants access to another principal")
		}
		hasUser = hasUser || sid.Equals(user)
	}
	if !hasUser {
		return errors.New("backup staging ACL does not include the current user")
	}
	return nil
}

func MkdirTemp(parent, prefix string) (string, error) {
	if parent == "" {
		parent = os.TempDir()
	}
	attributes, user, err := securityAttributes(true)
	if err != nil {
		return "", err
	}
	for range 10 {
		path := filepath.Join(parent, prefix+uuid.New().String())
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return "", err
		}
		if err := windows.CreateDirectory(name, attributes); errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		} else if err != nil {
			return "", err
		}
		handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err == nil {
			err = verifyPrivate(handle, user, true)
			err = errors.Join(err, windows.CloseHandle(handle))
		}
		if err != nil {
			_ = os.Remove(path)
			return "", err
		}
		return path, nil
	}
	return "", errors.New("cannot create private backup staging directory")
}

func CreateTemp(parent, prefix string) (*os.File, error) {
	if parent == "" {
		parent = os.TempDir()
	}
	attributes, user, err := securityAttributes(false)
	if err != nil {
		return nil, err
	}
	for range 10 {
		path := filepath.Join(parent, prefix+uuid.New().String())
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, err
		}
		handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(handle), path)
		if err := verifyPrivate(handle, user, false); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return nil, err
		}
		return file, nil
	}
	return nil, errors.New("cannot create private backup file")
}
