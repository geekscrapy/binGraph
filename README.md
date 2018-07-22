# binGraph
Simple tool to graph binary files (pretty much anything)

```
  $ python exeGraph_mpl.py --help
  usage: exeGraph_mpl.py [-h] -f file.exe [file.exe ...] [-o OUT] [--format png]
                         [--figsize # #] [--dpi 100] [-v] [-g]
                         {bin_hist,bin_ent} ...
  positional arguments:
    {bin_hist,bin_ent}

  optional arguments:
    -h, --help            show this help message and exit
    -f file.exe [file.exe ...], --file file.exe [file.exe ...]
                          Give me an entropy graph of this file!
    -o OUT, --out OUT     Graph output prefix - without extension!
    --format png          Graph output format
    --figsize # #         Figure width and height in inches
    --dpi 100             Figure dpi
    -v, --verbose         Print debug information to stderr
    -g                    Graph type
```

```
  $ exeGraph_mpl.py -f file.exe bin_hist --help
  usage: exeGraph_mpl.py bin_hist [-h] [--ignore_0] [--bins 1] [--log 1]
                                  [--ordered]
  optional arguments:
    -h, --help  show this help message and exit
    --ignore_0  Remove x00 from the graph, sometimes this blows other results
                due to there being numerous amounts - also see --log
    --bins 1    Sample bins
    --log 1     Amount of 'log' to apply to the graph
    --ordered   Add an ordered histogram - show overall distribution
```
    
```
  $ python exeGraph_mpl.py -f file.exe bin_ent --help
  usage: exeGraph_mpl.py bin_ent [-h] [-c 72] [--ibytes "{\"0's\": [0] ,
                                 \"Exploit\": [44, 144] }"]
  optional arguments:
    -h, --help            show this help message and exit
    -c 72, --chunks 72    Figure dpi
    --ibytes "{\"0's\": [0] , \"Exploit\": [44, 144] }"
                          JSON of bytes to include in the graph
```
