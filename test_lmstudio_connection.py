from app.analysis.proposers.lmstudio import LMStudioStaticProposer

test_chunk = {
    "chunk_id": "test-chunk-1",
    "source_file": "low.php",
    "source_code": """
<?php
if( isset( $_REQUEST[ 'Submit' ] ) ) {
    $id = $_REQUEST[ 'id' ];
    $query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
}
?>
""",
}

proposer = LMStudioStaticProposer()

findings = proposer.propose(
    application_name="DVWA",
    chunks=[test_chunk],
)

print("Execution report:", proposer.last_execution_report)
print("Findings returned:")
for f in findings:
    print(f)