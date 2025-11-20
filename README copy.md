This program can manage every Telesis TMC controller that can handle Extended protocol. Connection can be selected: serial port (usually COM1) or ethernet (ip and port must be set).

**INSTALLATION**: - copy the BMarkTmc folder anywhere in the target computer (please do NOT copy the full thing to desktop use C:\ or anything else more hidden in system to prevent the user accidentally deleting anything!).

&nbsp; - send a shortcut of the BMarkTMC.exe to desktop or anywhere the user will start the program.

**Purpose**: dynamic data transfer to the variable fields / query text buffer data fields of the ontroller based on a custom csv file.

**Process**: program Will transfer the data row by row than print. If no response (ready/done) in timeout a dialog will appear and user can select:

&nbsp; - repeat the same row and send the data again

&nbsp; - continue with next row

&nbsp; - stop (exit / abort)

**Default user** is:

&nbsp; admin, pw: admin

&nbsp; operator as op pw: op.

**WARNING**: These are ONLY for testing, for live usage adjust users and passwords as requested, NEVER leave default users in when delivering this for clients!

**Rights**:

&nbsp; **admin**:

&nbsp; - can **adjust seriasl settings** and data processing settings:

&nbsp; - all columns send as query text buffer, OR

&nbsp; - all columns send as variable text (one for every text field on the pattern, only recommended if you know what you are doing) OR

&nbsp; - specify for each column to be sent as query text buffer data or variable text field.

&nbsp; - adjust default pattern name

&nbsp; - adjust serial connection parameters

&nbsp; - can adjust users, add new usery, modify existing users, delete users

&nbsp; - can clear (archive) logs

&nbsp; - can do everything an operator can do

&nbsp; **operator**:

&nbsp; - can load CSV file for sending to controller

&nbsp; - can specify pattern name if not default (override default pattern)

&nbsp; - can connect to controller and can disconnect

&nbsp; - login/logout

&nbsp; - can modify row to be sent (Use Selected Start button)

&nbsp; - can start, stop and pause data transfer to controller

&nbsp; - can view logs

&nbsp; - filter for state (column called "state", values are dynamically set up from the content of the logs)

&nbsp; - filter for tags (\[TEXT] parts of the "line content column

&nbsp; - filter for custom texts of line content

&nbsp; - filter for date (day, week, there are arrow buttons for stepping days and weeks, if user is in day mode, week step button Will show logs for the day one week later/earlier)

&nbsp; - filter logs for custom date in YYYY.MM.DD formát "." is dynamically added if not entered
