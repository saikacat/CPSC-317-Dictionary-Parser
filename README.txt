//resolves nameserver edge case but breaks cname resolver
              Set<ResourceRecord> values = getResults(new DNSNode(nameserverRecords[0].getTextResult(), RecordType.A), 0);
            // ResourceRecord v = (ResourceRecord)values.toArray()[0];
            // retrieveResultsFromServer(node, v.getInetResult());
This line of code resolves the issue for the NS servers. But then 
It causes another issue with Cnames going on forever
The issue is because we aren't resolving the nameserver properly we can never backtrack the IP even though it returns it.