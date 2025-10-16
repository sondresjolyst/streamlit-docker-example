import streamlit as st
from common_authentication import authentication

st.title("Streamlit Docker Example")
st.write("Hello!")

debug_toggle = st.sidebar.toggle("Debug")
if "debug_toggle" not in st.session_state:
    st.session_state.debug_toggle = debug_toggle
st.session_state.debug_toggle = debug_toggle

authentication.verbose = st.session_state.debug_toggle
tokens = authentication.Tokens()
headers = authentication.Headers()

if authentication.verbose:
    with st.expander("sdf_db_token", expanded=False):
        st.write(tokens.sdf_db_token)
    with st.expander("database_token", expanded=False):
        st.write(tokens.database_token)
