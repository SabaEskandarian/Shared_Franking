# Shared_Franking

Code and data to accompany the paper "Abuse Reporting for Metadata-Hiding Communication Based on Secret Sharing."


The code requires OpenSSL installed. To run the code for the evaluation, run the following:

```
make shared_franking_eval
make plain_franking_eval
```

You can then run ``./shared_franking_eval`` to run the evaluation of shared franking or ``./plain_franking_eval`` to run the evaluation for plain franking.

The ``go/`` folder contains the code for additional supplemental components of the evaluation, mostly reported in the appendices. ``go/BeaverTest/`` contains code for measuring the online computation time of Beaver Multiplications. The other three subfolders of ``go/`` are for running the clients, moderator server, and other servers in an evaluation that sends the results of each step of the shared franking process over a network. 


See the artifact appendix (included in this repository for convenience) for more information about running the evaluation. 

#### Acknowledgment

This material is based upon work supported by the National Science Foundation under Grant No. 2234408. Any opinions, findings, and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the National Science Foundation.
