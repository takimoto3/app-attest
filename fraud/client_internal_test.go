package fraud

func (c *Client) GetHost() string {
	return c.inner.Host
}

func (c *Client) SetHost(host string) {
	c.inner.Host = host
}
