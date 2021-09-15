[![Work in MakeCode](https://classroom.github.com/assets/work-in-make-code-c53f0c86300af1a64cdd5dc830e2509efd17c8cb483a722cacaee84d10eb8ec9.svg)](https://classroom.github.com/online_ide?assignment_repo_id=4676420&assignment_repo_type=AssignmentRepo)

A Brief Description Of What This Application Is All About:

App is low level implementation of DNS server. Once program launches server starts waiting for incoming dns requests in a loop. Once query is received, search for responses is done as follows: THE FIRST STEP: Check local zone file, if answer is found here respond to client, if not go to the second step. THE SECOND STEP: Check local, in-memory cache. If still no success go to the third step. THE THIRD STEP: start iterative search outside the local configurations(Root -> TLD -> ...) to find authoritative name servers. THE FOURTH STEP: Forward initial query to authoritative name servers and get final response.

Note!!: Algrithm used during the third step is not the most optimal in terms of speed, but it gets the job done :)

I used "Struct" module to parse incoming byte streams(DNS queries/responses) to human friendly dictionaries and vise verca.

Project also includes "test.sh" file, which, as the name suggests, tests my implementation Note!!!: "test.sh" is hard-coded(file was provided the way it is), so there is a chance that expected results in test methods are outdated, so if test fails, it doesn't necessarily mean that I have a bug in my code.(manual check would be much appreciated in such cases)

main.py : main file which starts UDP socket, binds it to provided ip/port and provides dns service dns_decoder.py : class responsible for decoding incoming, binary dns queries dns_encoder.py : class responsible for encoding human friendly dns-packet representations into binary zone_file_manipulator.py : responsible for interaction with local zone files (used during the first step) dns_lookup.py : implements iterative search (used during the third step) cache.py: represents in-memory cache
