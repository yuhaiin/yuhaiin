package main

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

func main() {
	baseKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters`, registry.READ)
	if err != nil {
		fmt.Println("Registry not found:", err)
		return
	}
	defer baseKey.Close()

	ifces, err := baseKey.ReadSubKeyNames(-1)
	if err != nil {
		fmt.Println("Registry not found:", err)
		return
	}

	fmt.Println(ifces)

	for _, iface := range ifces {
		subKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\`+iface+`\DohInterfaceSettings\Doh`, registry.READ)
		if err != nil {
			fmt.Println("Registry not found:", err)
			continue
		}
		defer subKey.Close()

		subKeyNames, err := subKey.ReadSubKeyNames(-1)
		if err != nil {
			fmt.Println("Registry not found:", err)
			continue
		}

		fmt.Println(subKeyNames)

		for _, subKeyName := range subKeyNames {
			baseKey, err = registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\`+iface+`\DohInterfaceSettings\Doh\`+subKeyName, registry.READ)
			if err != nil {
				fmt.Println("Registry not found:", err)
				continue
			}
			defer baseKey.Close()

			fmt.Println(baseKey.GetStringValue("DohTemplate"))
		}
	}
}
