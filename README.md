# binGraph.py
Simple tool to graph files for quick analysis

Allows you to create matplotlib graphs to represent different aspects of a file (usually malware). Focusing on entropy graphs

Given a file(s) (with ```--file```) different graphs can be generated (e.g. ```bin_ent```, ```bin_hist``` etc.) or ```all``` can be used to generate all the graphs available for that file.

Below are the ```--help ``` options:

```
$ python binGraph.py --help
usage: binGraph.py [-h] -f malware.exe [malware.exe ...] [-] [-p PREFIX]
                   [-d /data/graphs/] [--format png] [--figsize # #]
                   [--dpi 100] [-v]
                   {all,bin_ent,bin_hist} ...

positional arguments:
  {all,bin_ent,bin_hist}
                        Graph type to generate

optional arguments:
  -h, --help            show this help message and exit
  -f malware.exe [malware.exe ...], --file malware.exe [malware.exe ...]
                        Give me a graph of this file. See - if this is the
                        only argument specified.
  -                     *** Required if --file or -f is the only argument
                        given before a graph type is given (it's greedy!).
                        E.g. "binGraph.py --file mal.exe - bin_ent"
  -p PREFIX, --prefix PREFIX
                        Saved graph output filename (without extension)
  -d /data/graphs/, --save_dir /data/graphs/
                        Where to save the graph files
  --format png          Graph output format
  --figsize # #         Figure width and height in inches
  --dpi 100             Figure dpi
  -v, --verbose         Print debug information to stderr
```


![Binary entropy graph](https://github.com/geekscrapy/binGraph/blob/public/example-bin_ent.png "Binary entropy graph - from PE executable")
!MALWARE! From: https://cape.contextis.com/file/CAPE/9472/ad5a729e7c4047c946601e5533b1dfa3983a0d84da61b743dda1ca3b1c956ec5/
```
$ python binGraph.py bin_ent --help
usage: binGraph.py bin_ent [-h] [-c 72] [--ibytes "{\"0's\": [0] ,
                           \"Exploit\": [44, 144] }"]

optional arguments:
  -h, --help            show this help message and exit
  -c 72, --chunks 72    Defines how many chunks the binary is split into (and
                        therefore the amount of bytes submitted for shannon
                        sampling per time). Higher number gives more detail
  --ibytes "{\"0's\": [0] , \"Exploit\": [44, 144] }"
                        JSON of bytes to include in the graph
```


![Binary byte histogram](https://github.com/geekscrapy/binGraph/blob/public/example-bin_hist.png "Binary byte histogram")
!MALWARE! From: https://cape.contextis.com/file/CAPE/9472/ad5a729e7c4047c946601e5533b1dfa3983a0d84da61b743dda1ca3b1c956ec5/
```
$ python binGraph.py bin_hist --help
usage: binGraph.py bin_hist [-h] [--ignore_0] [--bins 1] [--log 1] [--ordered]

optional arguments:
  -h, --help  show this help message and exit
  --ignore_0  Remove x00 from the graph, sometimes this blows other results
              due to there being numerous amounts - also see --log
  --bins 1    Sample bins
  --log 1     Amount of 'log' to apply to the graph
  --ordered   Add an ordered histogram - show overall distribution
```
