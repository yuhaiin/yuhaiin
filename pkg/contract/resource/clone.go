package resource

import "slices"

func cloneQuotas(quotas []Quota) []Quota {
	result := slices.Clone(quotas)
	for i := range result {
		result[i].Thresholds = slices.Clone(result[i].Thresholds)
	}
	return result
}

func CloneConfig(c Config) Config {
	c.DefaultUser.Quotas = cloneQuotas(c.DefaultUser.Quotas)
	c.Groups = slices.Clone(c.Groups)
	for i := range c.Groups {
		c.Groups[i].Quotas = cloneQuotas(c.Groups[i].Quotas)
	}
	c.Users = slices.Clone(c.Users)
	for i := range c.Users {
		c.Users[i].Policy.Quotas = cloneQuotas(c.Users[i].Policy.Quotas)
	}
	c.Credentials = slices.Clone(c.Credentials)
	for i := range c.Credentials {
		c.Credentials[i].Policy.Quotas = cloneQuotas(c.Credentials[i].Policy.Quotas)
	}
	return c
}
