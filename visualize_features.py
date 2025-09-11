import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("apk_features.csv")

# Risk score distribution
plt.figure(figsize=(6,4))
df["risk_score"].hist(bins=10, color="skyblue", edgecolor="black")
plt.title("Risk Score Distribution")
plt.xlabel("Risk Score")
plt.ylabel("Count")
plt.savefig("risk_score_distribution.png")
plt.close()

# Dangerous permissions
plt.figure(figsize=(6,4))
df.groupby("label")["num_dangerous_permissions"].mean().plot(kind="bar", color=["green","red"])
plt.title("Avg. Dangerous Permissions: Legit vs Fake")
plt.xticks([0,1], ["Legit (0)", "Fake (1)"])
plt.ylabel("Avg. Dangerous Permissions")
plt.savefig("dangerous_permissions.png")
plt.close()

# Activities comparison
plt.figure(figsize=(6,4))
df.groupby("label")["num_activities"].mean().plot(kind="bar", color=["blue","orange"])
plt.title("Avg. Activities: Legit vs Fake")
plt.xticks([0,1], ["Legit (0)", "Fake (1)"])
plt.ylabel("Avg. Activities")
plt.savefig("activities_comparison.png")
plt.close()

print("✅ Graphs saved: risk_score_distribution.png, dangerous_permissions.png, activities_comparison.png")
