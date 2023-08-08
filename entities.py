class Rule:
    
    def __init__(self, id, rule_type, since, until, filters, regex, ):
        self.id = id
        self.rule_type = rule_type
        self.since = since
        self.until = until
        if filters:
            self.filters = filters.split(',')
        self.regex = regex
