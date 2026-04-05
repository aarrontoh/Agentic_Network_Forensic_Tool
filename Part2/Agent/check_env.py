import os
from pathlib import Path

def check_env():
    env_path = Path(".env")
    if not env_path.exists():
        print("❌ Error: .env file not found in Part2/Agent/")
        print("💡 Tip: Copy .env.example to .env and add your keys.")
        return

    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("GOOGLE_API_KEY", "").strip()
    
    print("✅ .env file detected.")
    
    if openai_key:
        print(f"✅ OpenAI API Key: Loaded (Starts with {openai_key[:6]}...)")
    else:
        print("⚠️ OpenAI API Key: Not found in .env")

    if gemini_key:
        print(f"✅ Gemini API Key: Loaded (Starts with {gemini_key[:6]}...)")
    else:
        print("⚠️ Gemini API Key: Not found in .env")

    if not openai_key and not gemini_key:
        print("❌ Error: No API keys were loaded. Make sure .env is correctly formatted.")
    else:
        print("\n🚀 You are ready to run the agent in Autonomous Mode!")

if __name__ == "__main__":
    check_env()
