from ai_security_advisor.collector import collect_events

df = collect_events()
print(df.head())

