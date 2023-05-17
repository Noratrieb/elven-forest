import pandas as pd
import sys
import plotly.express as px

df = pd.read_csv(sys.argv[1])
#df = df[df['1'] == "rustc_middle[8d82ae2353292c40]"]

print(df)

fig = px.treemap(df, path=[px.Constant("functions"), '1', '2', '3', '4'], values='size',
                  hover_data=['size'])
fig.update_layout(margin = dict(t=50, l=25, r=25, b=25))
print("finished")


fig.write_image("output.svg")
print("written")