import streamlit as st
from web3 import Web3
import json
from hexbytes import HexBytes

# ====================================================================
# 🎨 STREAMLIT CONFIGURATION AND UI STYLING
# ====================================================================
st.set_page_config(page_title="Blockchain Certificate DApp", layout="centered")

# Basic CSS
st.markdown("""
<style>
/* Streamlit's main content area */
.main > div {
    padding-top: 1rem;
}
body {background-color: #f3f7ff;}
.block {
    padding:20px;
    background:white;
    border-radius:10px;
    box-shadow:0 2px 10px rgba(0,0,0,0.1);
}
input, select, textarea {
    border-radius: 6px !important;
}
.stTabs [data-baseweb="tab-list"] {
    gap: 24px;
}
.stTabs [data-baseweb="tab"] {
    font-size: 18px;
    padding: 10px 16px;
}
</style>
""", unsafe_allow_html=True)


# ====================================================================
# 🔗 BLOCKCHAIN CONNECTION AND CONFIG
# ====================================================================

# NOTE: You MUST replace these with your actual deployed values.
RPC_URL = "http://127.0.0.1:7545"
CONTRACT_ADDRESS = "0xB7e3AabF140B1bd78bC7B699Af247BbaCA02b574" # Example address

try:
    web3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not web3.is_connected():
        st.error(f"Cannot connect to Ganache node at {RPC_URL}. Please ensure Ganache is running.")
        st.stop()

    # NOTE: Ensure 'contract/OCertificate.json' exists and contains the ABI
    with open("contract/OCertificate.json") as f:
        contract_json = json.load(f)
        abi = contract_json["abi"]

    CONTRACT_ADDRESS_C = Web3.to_checksum_address(CONTRACT_ADDRESS)
    contract = web3.eth.contract(address=CONTRACT_ADDRESS_C, abi=abi)
    
    # Fetch Admin address (used for role verification)
    ADMIN_ADDRESS = contract.functions.admin().call()
    
except FileNotFoundError:
    st.error("ABI file 'contract/OCertificate.json' not found. Please compile the contract.")
    st.stop()
except Exception as e:
    st.error(f"Error initializing Web3 connection or contract: {e}")
    st.stop()


# -----------------------------
# Hex/Bytes32 Converter
# -----------------------------
def hex_to_bytes32(hex_string):
    """Converts a hex string (with or without 0x) to bytes32 format."""
    if not isinstance(hex_string, str):
        raise TypeError("Input must be a hex string.")
        
    if hex_string.startswith("0x"):
        hex_string = hex_string[2:]
        
    if len(hex_string) > 64:
        raise ValueError("Hash is too long for bytes32.")
        
    # Pad to 64 chars, then convert
    padded_hex = hex_string.zfill(64)
    return bytes.fromhex(padded_hex)

# -----------------------------
# Role Detection
# -----------------------------
def detect_role(addr):
    try:
        addr = Web3.to_checksum_address(addr)
        if addr == Web3.to_checksum_address(ADMIN_ADDRESS): 
            return "Admin" 
        if contract.functions.isIssuer(addr).call():
            return "Issuer"
        if contract.functions.isStudent(addr).call():
            return "Student"
        return "Public"
    except:
        return "Public"


# ====================================================================
# 💻 SESSION STATE & ROUTER
# ====================================================================

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.address = None

def logout():
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.address = None
    
# ====================================================================
# 🏠 LOGIN PAGE (SECURE INPUT REVERTED)
# ====================================================================
def login_page():
    st.title("🔐 Blockchain Certificate System")
    st.subheader("Login")

    tab_wallet, tab_public = st.tabs(["Wallet Login (Admin/Issuer/Student)", "Public Verifier"])
    
    with tab_wallet:
        st.markdown("---")
        st.info("Log in with your wallet address.")
        
        addr = st.text_input("Enter Your Wallet Address (e.g., 0x...)")

        if st.button("Login"):
            if not web3.is_address(addr):
                st.error("Invalid Ethereum address.")
                return

            checksum_addr = Web3.to_checksum_address(addr)
            role = detect_role(checksum_addr)

            st.session_state.logged_in = True
            st.session_state.address = checksum_addr
            st.session_state.role = role

            st.success(f"Successfully logged in as **{role}**")
            st.rerun()
            
    with tab_public:
        st.markdown("---")
        st.markdown("Click below to proceed to the verification page without a wallet.")
        if st.button("Proceed as Public Verifier"):
            st.session_state.logged_in = True
            st.session_state.address = "0x0000000000000000000000000000000000000000"
            st.session_state.role = "Public"
            st.success("Proceeding as Public Verifier.")
            st.rerun()


# ====================================================================
# 👑 ADMIN PANEL
# ====================================================================
def admin_page():
    st.title("🛠️ Admin Dashboard")
    st.sidebar.markdown(f"**Role:** {st.session_state.role}")
    st.sidebar.markdown(f"**Address:** `{st.session_state.address}`")
    st.sidebar.button("Logout", on_click=logout)

    st.markdown("### Manage Roles")

    action = st.selectbox("Select Action", [
        "Add Issuer", "Remove Issuer",
        "Add Student", "Remove Student"
    ])

    target = st.text_input("Target Wallet Address (to Add/Remove)")
    
    target_addr = None
    if target:
        try:
            target_addr = Web3.to_checksum_address(target)
        except:
            st.warning("Invalid target address format.")
            return

    if st.button("Execute"):
        if not target_addr:
            st.error("Please enter a valid Ethereum address.")
            return
            
        try:
            if action == "Add Issuer":
                function_call = contract.functions.addIssuer(target_addr)
            elif action == "Remove Issuer":
                function_call = contract.functions.removeIssuer(target_addr)
            elif action == "Add Student":
                function_call = contract.functions.addStudent(target_addr)
            elif action == "Remove Student":
                function_call = contract.functions.removeStudent(target_addr)
            else:
                return

            # Using the working .transact pattern
            tx = function_call.transact({"from": st.session_state.address})

            st.success(f"Transaction Successful: {tx.hex()}")
        except Exception as e:
            st.error(f"Transaction execution failed: {e}")

    # --- Verification ---
    st.markdown("---")
    st.markdown("### Verify Certificate Status")
    cert_hash = st.text_input("Certificate Hash (bytes32 format, e.g., 0x...)")
    if st.button("Verify Certificate"):
        try:
            cert_id_bytes = hex_to_bytes32(cert_hash)
            val = contract.functions.verifyCertificate(cert_id_bytes).call()
            status = "✅ VALID" if val else "❌ REVOKED / NOT FOUND"
            st.info(f"Verification Result: **{status}**")
        except Exception as e:
            st.error(f"Error during verification: {e}")


# ====================================================================
# 🏫 ISSUER PANEL
# ====================================================================
def issuer_page():
    st.title("🏫 Issuer Dashboard")
    st.sidebar.markdown(f"**Role:** {st.session_state.role}")
    st.sidebar.markdown(f"**Address:** `{st.session_state.address}`")
    st.sidebar.button("Logout", on_click=logout)

    tab_issue, tab_revoke = st.tabs(["Issue Certificate", "Revoke Certificate"])

    # --- Issue Certificate Tab ---
    with tab_issue:
        st.subheader("Issue New Certificate")
        student_addr_input = st.text_input("Student Address (e.g., 0x...)")
        student_addr = None
        if student_addr_input:
             try:
                student_addr = Web3.to_checksum_address(student_addr_input)
             except:
                st.warning("Invalid student address format.")
                return

        name = st.text_input("Student Name")
        uid = st.text_input("Unique ID (UID)")
        course = st.text_input("Course Name")
        date = st.text_input("Issue Date (e.g., 2024-01-01)")

        if st.button("✅ Issue Certificate"):
            if not student_addr:
                st.error("Please provide a valid recipient address.")
                return

            try:
                # Using the working .transact pattern
                tx = contract.functions.issueCertificate(
                    student_addr, name, uid, course, date
                ).transact({"from": st.session_state.address})
                
                st.success(f"Issued! TX: {tx.hex()}")
            except Exception as e:
                st.error(f"Transaction execution failed: {e}")



    # --- Revoke Certificate Tab ---
    with tab_revoke:
        st.subheader("Revoke Issued Certificate")
        cert_hash = st.text_input("Certificate Hash to Revoke (bytes32, e.g., 0x...)")
        if st.button("🚫 Revoke Certificate"):
            if not cert_hash.strip():
                st.warning("Please enter a certificate hash.")
                return
            
            try:
                cert_id_bytes = hex_to_bytes32(cert_hash)
                # Using the working .transact pattern
                tx = contract.functions.revokeCertificate(cert_id_bytes).transact({"from": st.session_state.address})
                
                st.success(f"Revoked! TX: {tx.hex()}")
            except Exception as e:
                st.error(f"Transaction execution failed: {e}")


# ====================================================================
# 🎓 STUDENT PANEL
# ====================================================================
def student_page():
    st.title("🎓 Student Dashboard")
    st.sidebar.markdown(f"**Role:** {st.session_state.role}")
    st.sidebar.markdown(f"**Address:** `{st.session_state.address}`")
    st.sidebar.button("Logout", on_click=logout)

    st.subheader("My Certificates")

    if st.button("Show My Certificates"):
        try:
            certs = contract.functions.getMyCertificates().call({"from": st.session_state.address})

            if len(certs) == 0:
                st.info("No certificates found.")
                return

            st.subheader("Your Certificates")

            for c in certs:
                hex_id = Web3.to_hex(c)
                st.code(hex_id)

        except Exception as e:
            st.error(f"Error fetching certificates: {e}")



    st.markdown("---")
    st.subheader("View Certificate Details")
    cert_hash = st.text_input("Enter Certificate Hash to view details (e.g., 0x...)")

    if st.button("View Certificate Details"):
        if cert_hash.strip() == "":
            st.warning("Please enter a certificate hash.")
            return

        try:
            cert_id_bytes = hex_to_bytes32(cert_hash)
            # The .call() needs the sender address for the 'require' check in getCertificate
            data = contract.functions.getCertificate(cert_id_bytes).call({"from": st.session_state.address})

            st.json({
                "Name": data[0],
                "UID": data[1],
                "Course": data[2],
                "Issue Date": data[3],
                "Student": data[4],
                "Issuer": data[5],
                "Valid": "✅ VALID" if data[6] else "❌ REVOKED"
            })

        except Exception as e:
            st.error(f"Access denied or Certificate not found. Error: {e}")


# ====================================================================
# 🔍 PUBLIC VERIFIER
# ====================================================================
def public_page():
    st.title("🔍 Public Certificate Verification")
    st.sidebar.markdown(f"**Role:** {st.session_state.role}")
    st.sidebar.markdown(f"**Address:** `Public Access`")
    st.sidebar.button("Go to Login", on_click=logout)
    
    st.markdown("---")

    cert_hash = st.text_input("Enter Certificate Hash (bytes32, e.g., 0x...)")

    if st.button("Verify Status"):
        if not cert_hash.strip():
            st.warning("Please enter a certificate hash.")
            return
            
        try:
            cert_id_bytes = hex_to_bytes32(cert_hash)
            valid = contract.functions.verifyCertificate(cert_id_bytes).call()
            
            if valid:
                st.success("✅ Certificate is **VALID** on the blockchain.")
            else:
                st.error("❌ Certificate is **REVOKED** or **NOT FOUND**.")
        except Exception as e:
            st.error(f"Error during verification: {e}")


# ====================================================================
# 🚦 ROUTER
# ====================================================================

if not st.session_state.logged_in:
    login_page()
    #pass


else:
    try:
        if st.session_state.role == "Admin":
            admin_page()
        elif st.session_state.role == "Issuer":
            issuer_page()
        elif st.session_state.role == "Student":
            student_page()
        elif st.session_state.role == "Public":
            public_page()
        else:
            public_page()
    except Exception as e:
        st.error(f"A severe connection or contract error occurred. Please refresh or re-login. Error: {e}")
        logout()