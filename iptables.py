import iptc

def insert_rule():
    rule = iptc.Rule()
    match = iptc.Match(rule, "mac")
    match.mac_source = "b0:35:9f:c3:af:e1"
    rule.add_match(match)
    rule.target = iptc.Target(rule, "DROP")
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "FORWARD")
    #chain.insert_rule(rule)
    chain.delete_rule(rule)


if __name__ == "__main__":
    insert_rule()