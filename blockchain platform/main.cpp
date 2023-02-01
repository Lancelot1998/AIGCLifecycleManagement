#define _CRT_SECURE_NO_WARNINGS
#include<cstdio>
#include<string>
#include<cstring>
#include<map>
#include<iostream>
#include <fstream>
#define maxn 1024
using namespace std;

map<string, int>num;//节点名字对应的节点编号
string name[maxn];//节点编号对应的节点名字
int id = 2;
string st;
int ans, head[maxn], net[maxn], ver[maxn];//表示树的结构
int v[maxn], d[maxn], T, n;//d代表从当前节点开始往下走最远的距离
int link1, link2, linkx;
int son[maxn];//当前节点的d值是从哪个孩子节点更新过来的
int stack[maxn], top;//存储答案
int root;

///////////////////////////
int ioIndex = 0;
extern "C" {
	void test(int a,char *inp,char * outp);
}
////////////////////////////
void initialize() {

	memset(v, 0, sizeof(v));
	memset(head, 0, sizeof(v));
	memset(net, 0, sizeof(v));
	memset(ver, 0, sizeof(v));
	memset(v, 0, sizeof(v));
	memset(d, 0, sizeof(v));
	memset(son, 0, sizeof(v));
	memset(stack, 0, sizeof(v));

}


void dp(int x) {
	v[x] = 1;
	for (int i = head[x]; i; i = net[i]) {
		int y = ver[i];
		if (v[y]) continue;
		dp(y);
		if (d[x] + d[y] + 1 > ans) {//假设当前节点就是树干上分叉的那个点，更新ans
			ans = d[x] + d[y] + 1;
			linkx = x;
			link1 = y;
			link2 = son[x];
		}
		if (d[y] + 1 > d[x]) {//如果当前节点往下从y走更长那么就用y替son[x]
			d[x] = d[y] + 1;
			son[x] = y;
		}
	}
}

void add(int x, int y) {
	ver[T] = y;
	net[T] = head[x];
	head[x] = T++;
}

void print1(int x) {
	if (son[x])print1(son[x]);
	stack[top++] = x;
}

void print2(int x) {
	stack[top++] = x;
	if (son[x])print2(son[x]);
}

void test(int a,char *inp,char * outp) {
	initialize();
	ifstream input(inp);
	ofstream output(outp);
	//scanf("%d", &n);
	//name[1] = p[ioIndex++];
	input  >> name[1];
	num[name[1]] = 1;
	root = 1;
	T = 1;
	for (int i = 1; i < a; i++) {
		int x, y;
		//st = p[ioIndex++];
		input >> st;
	

		if (num.find(st) == num.end()) {
			name[id] = st;
			num[st] = id++;
		}
		x = num[st];

		//st = p[ioIndex++]; 
		input >> st;
		

		if (num.find(st) == num.end()) {
			name[id] = st;
			num[st] = id++;
		}
		y = num[st];
		add(x, y);//i+1的父亲是x
		add(y, x);
	}
	dp(root);
	output << d[root]+1 <<endl;
	int x = root;
	output << name[root] << endl;
	while (son[x] != 0) {
		x = son[x];
		output << name[x] << endl;
	}
	input.close();
	output << flush; output.close(); 
}

int main()
{
	return 0;
}

