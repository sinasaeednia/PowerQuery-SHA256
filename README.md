# PowerQuery SHA256 function
Provides SHA256 hashkey for integrity and incrememntal checks accross power Query enables applications (Power BI, Excel, ...)

Copy and paste the whole SHA256.pq content into a new Power Query Blank Query. It should show up as fx in the list of queries pane (on the left), indicating that it's confirmed as being a function.

The function input should be a text string (not list, not table, not anything else). As an example use case, it can be used as a function to create a new column contaning teh SHA256 hash code of another column with text values. 

```Table.AddColumn(#"Previous Step", "SHA256", each **SHA256**([ColumnNameAsInput]))```

Note: Handle the edge cases like empty, error, and incompatible inputs in your code
