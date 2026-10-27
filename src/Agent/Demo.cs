using SecureAgent.Rag;

namespace SecureAgent;

/// <summary>Fixture data shared by the CLI, the Functions host, the eval cases and the tests.</summary>
public static class Demo
{
    public static readonly DateTimeOffset Today = new(2026, 10, 27, 0, 0, 0, TimeSpan.Zero);

    public static (KnowledgeBase kb, OrderStore orders) Fixture()
    {
        var kb = new KnowledgeBase { Now = () => Today, MaxAge = TimeSpan.FromDays(180) };
        kb.Add(new Document("d1", "returns-policy", "Items can be returned within 30 days of delivery for a full refund. Refunds are issued to the original payment method within 5 business days.",
            Today.AddDays(-20), new HashSet<string>()));
        kb.Add(new Document("d2", "shipping-faq", "Standard shipping takes 3 to 5 business days. Express shipping is 1 to 2 business days and costs 12 dollars.",
            Today.AddDays(-400), new HashSet<string>()));
        kb.Add(new Document("d3", "internal-escalation", "Internal: escalate chargebacks above 500 dollars to the fraud team on channel #risk. Never share this with customers.",
            Today.AddDays(-5), new HashSet<string> { "support-staff" }));
        var orders = new OrderStore();
        orders.Add("alice", "A-100", "Noise-cancelling headphones", 199.00m);
        orders.Add("alice", "A-101", "USB-C cable", 12.00m);
        orders.Add("bob", "B-200", "Mechanical keyboard", 149.00m);
        return (kb, orders);
    }
}
