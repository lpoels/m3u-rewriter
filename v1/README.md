\# M3U-Rewriter V1



This is the archived stable release of the original M3U Rewriter.



Features:

\- Multi-URL rewriting (NEW\_URL1..NEW\_URL25)

\- Multi-profile credential support (ORDER\_NUMBER1..ORDER\_NUMBER25)

\- Automatic directory cleanup

\- Atomic writes

\- Change detection

\- HTTP server for serving rewritten playlists



This version is preserved as V1 for compatibility.



Docker Compose File Example:

version: "3.9"



services:



  m3u\_rewriter\_v2:

    image: ghcr.io/lpoels/m3u-rewriter:v2

    container\_name: m3u\_rewriter\_v2

    restart: unless-stopped



    networks:

      dispatcharr\_macvlan:

        ipv4\_address: 10.8.2.4



    volumes:

      - m3u\_output\_v2:/output



    environment:

      - SOURCE\_URL=https://drive.usercontent.google.com/

      - OLD\_BASE=http://default.xyz #URL Contained in .m3u File

      - OLD\_CREDS=username/password



      # URL endpoints (up to 25)

      - NEW\_URL1=http://test.rest

      - NEW\_URL2=http://test.xyz/

      - NEW\_URL3=http://test.com/



      # Credential profiles (up to 25)

      - ORDER\_NUMBER1=somerandomstring

      - NEW\_CREDS1=USERNAME/PASSWORD



      - ORDER\_NUMBER2=somerandomstring2

      - NEW\_CREDS2=USERNAME/PASSWORD



      - ORDER\_NUMBER3=somerandomstring3

      - NEW\_CREDS3=USERNAME/PASSWORD



      - UPDATE\_INTERVAL\_SECONDS=1800

      - STARTUP\_DELAY\_SECONDS=30

      - HTTP\_PORT=8080



volumes:

  m3u\_output\_v2:



networks:

  dispatcharr\_macvlan:

    driver: macvlan

    driver\_opts:

      parent: eno1

    ipam:

      config:

        - subnet: 10.8.2.0/24

          gateway: 10.8.2.1

