#!/usr/bin/bash
average=0
index=0
directory=$1
for file in `ls $directory`
  do 
	 if test -r $directory/$file/out/Metric_UnreachableFunctions.csv
	 then 
	     all=`cat $directory/$file/out/Metric_PrivateFunctions.csv | wc -l`;
	     unreach=`cat $directory/$file/out/Metric_UnreachableFunctions.csv | wc -l`;
	     if [ $all != 0 ] 
	     then
                index=`expr $index + 1`
		echo $file;
                echo "#private functions: $all";
                echo "#unreachable functions: $unreach";
                coverage=`echo "(($all) - ($unreach)) / ($all)" | bc -l`;
		echo "coverage: $coverage";
                average=`echo "(($average * ($index-1)) + $coverage) / $index" | bc -l`;
		echo "" ;
             fi; 
	 fi; 
done

echo "Average private function coverage (over all successfully-analyzed contracts with private functions)"
echo $average;
echo
