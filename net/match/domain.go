package match

import (
	"log"
	"strings"
)

type domainNode struct {
	isLast bool
	mark   interface{}
	child  map[string]*domainNode
}

type Domain struct {
	root *domainNode
}

func (d *Domain) Insert(domain string, mark interface{}) {
	tmp := d.root
	domainDiv := strings.Split(domain, ".")
	for index := range domainDiv {
		if index == 0 && domainDiv[index] == "www" {
			continue
		}
		if _, ok := tmp.child[domainDiv[index]]; !ok {
			tmp.child[domainDiv[index]] = &domainNode{
				isLast: false,
				child:  map[string]*domainNode{},
			}
		}
		if index == len(domainDiv)-1 {
			tmp.child[domainDiv[index]].isLast = true
			tmp.child[domainDiv[index]].mark = mark
		}
		tmp = tmp.child[domainDiv[index]]
	}
}
func (d *Domain) InsertFlip(domain string, mark interface{}) {
	tmp := d.root
	domainDiv := strings.Split(domain, ".")
	for index := len(domainDiv) - 1; index >= 0; index-- {
		if _, ok := tmp.child[domainDiv[index]]; !ok {
			tmp.child[domainDiv[index]] = &domainNode{
				isLast: false,
				child:  map[string]*domainNode{},
			}
		}
		if index == 0 {
			tmp.child[domainDiv[index]].isLast = true
			tmp.child[domainDiv[index]].mark = mark
		}
		tmp = tmp.child[domainDiv[index]]
	}
}

func (d *Domain) Search(domain string) (isMatcher bool, mark interface{}) {
	root := d.root
	first, domainDiv := true, strings.Split(domain, ".")
	l := len(domainDiv)
	for index := range domainDiv {
		log.Println(domainDiv[index], index, len(domainDiv))
		_, ok := root.child[domainDiv[index]] // use index to get data quicker than new var

		if first && !ok {
			log.Println("first , !ok")
			continue
		}

		if !ok {
			log.Println("!ok", domainDiv[index])
			return false, nil
		}

		if index == l-1 {
			if root.child[domainDiv[index]].isLast == true {
				return true, root.child[domainDiv[index]].mark
			}
			return false, nil
		}

		log.Println("ok", domainDiv[index])
		root = root.child[domainDiv[index]]
		first = false
	}
	return false, nil
}

func (d *Domain) SearchFlip(domain string) (isMatcher bool, mark interface{}) {
	root := d.root
	domainDiv := strings.Split(domain, ".")
	for index := len(domainDiv) - 1; index >= 0; index-- {
		_, ok := root.child[domainDiv[index]] // use index to get data quicker than new var
		if !ok {
			//log.Println("!ok", domainDiv[index])
			return false, nil
		}
		if root.child[domainDiv[index]].isLast == true {
			return true, root.child[domainDiv[index]].mark
		}
		root = root.child[domainDiv[index]]
	}
	return false, nil
}

func NewDomainMatch() *Domain {
	return &Domain{root: &domainNode{
		isLast: false,
		child:  map[string]*domainNode{},
	}}
}
